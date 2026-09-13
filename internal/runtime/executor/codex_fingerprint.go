package executor

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

type codexFingerprintMode uint8

const (
	codexFingerprintModeOff codexFingerprintMode = iota
	codexFingerprintModeDevice
	codexFingerprintModeSession
	codexFingerprintModeFull
)

type codexFingerprintReplacement struct {
	kind     string
	original string
	mapped   string
}

func codexFingerprintPolicy(auth *cliproxyauth.Auth) (codexFingerprintMode, string) {
	if auth == nil {
		return codexFingerprintModeOff, ""
	}
	mode := codexFingerprintValue(auth, "codex_fingerprint_mode", "codex-fingerprint-mode")
	seed := codexFingerprintValue(auth, "codex_fingerprint_seed", "codex-fingerprint-seed")
	if seed == "" {
		seed = strings.TrimSpace(auth.ID)
	}
	switch strings.ToLower(mode) {
	case "device":
		return codexFingerprintModeDevice, seed
	case "session":
		return codexFingerprintModeSession, seed
	case "full":
		return codexFingerprintModeFull, seed
	default:
		return codexFingerprintModeOff, seed
	}
}

func codexFingerprintValue(auth *cliproxyauth.Auth, keys ...string) string {
	for _, key := range keys {
		if auth.Attributes != nil {
			if value := strings.TrimSpace(auth.Attributes[key]); value != "" {
				return value
			}
		}
	}
	for _, key := range keys {
		if auth.Metadata == nil {
			continue
		}
		if value, ok := auth.Metadata[key].(string); ok {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}

func applyCodexFingerprintBody(auth *cliproxyauth.Auth, userPayload []byte, rawJSON []byte, state codexIdentityConfuseState) ([]byte, codexIdentityConfuseState) {
	mode, seed := codexFingerprintPolicy(auth)
	if mode == codexFingerprintModeOff || seed == "" || len(rawJSON) == 0 {
		return rawJSON, state
	}
	state.fingerprintMode = mode
	state.fingerprintSeed = seed

	for _, identity := range []struct {
		minimum codexFingerprintMode
		kind    string
		create  bool
		paths   []string
	}{
		{
			minimum: codexFingerprintModeDevice,
			kind:    "installation",
			create:  true,
			paths:   []string{"client_metadata.x-codex-installation-id", "client_metadata.installation_id"},
		},
		{
			minimum: codexFingerprintModeSession,
			kind:    "session",
			paths: []string{
				"session_id", "session-id", "conversation_id", "conversation-id",
				"client_metadata.session_id", "client_metadata.session-id",
				"client_metadata.conversation_id", "client_metadata.conversation-id",
			},
		},
		{
			minimum: codexFingerprintModeFull,
			kind:    "cache",
			paths:   []string{"prompt_cache_key", "client_metadata.prompt_cache_key"},
		},
		{
			minimum: codexFingerprintModeFull,
			kind:    "thread",
			paths: []string{
				"thread_id", "parent_thread_id", "forked_from_thread_id", "forked_from_id", "root_thread_id",
				"client_metadata.thread_id", "client_metadata.parent_thread_id",
				"client_metadata.forked_from_thread_id", "client_metadata.forked_from_id",
				"client_metadata.root_thread_id", "client_metadata.x-codex-parent-thread-id",
			},
		},
		{
			minimum: codexFingerprintModeFull,
			kind:    "turn",
			paths: []string{
				"turn_id", "parent_turn_id", "root_turn_id",
				"client_metadata.turn_id", "client_metadata.parent_turn_id", "client_metadata.root_turn_id",
			},
		},
		{
			minimum: codexFingerprintModeFull,
			kind:    "window",
			paths: []string{
				"window_id", "client_metadata.window_id", "client_metadata.x-codex-window-id",
			},
		},
		{
			minimum: codexFingerprintModeFull,
			kind:    "request",
			paths: []string{
				"request_id", "client_request_id", "client_metadata.request_id",
				"client_metadata.client_request_id", "client_metadata.x-client-request-id",
			},
		},
	} {
		if mode < identity.minimum {
			continue
		}
		for _, path := range identity.paths {
			rawJSON = rewriteCodexFingerprintPath(userPayload, rawJSON, identity.kind, identity.create, &state, path)
		}
	}

	originalTurnMetadata := codexFingerprintTurnMetadata(userPayload)
	currentTurnMetadata := codexFingerprintTurnMetadata(rawJSON)
	if currentTurnMetadata == "" {
		currentTurnMetadata = originalTurnMetadata
	}
	if currentTurnMetadata != "" {
		updated := rewriteCodexFingerprintTurnMetadata(originalTurnMetadata, currentTurnMetadata, &state)
		rawJSON, _ = sjson.SetBytes(rawJSON, "client_metadata.x-codex-turn-metadata", updated)
	}
	return rawJSON, state
}

func rewriteCodexFingerprintPath(userPayload []byte, rawJSON []byte, kind string, create bool, state *codexIdentityConfuseState, path string) []byte {
	original := strings.TrimSpace(gjson.GetBytes(userPayload, path).String())
	current := strings.TrimSpace(gjson.GetBytes(rawJSON, path).String())
	if original == "" {
		original = current
	}
	if original == "" || current == "" && !create {
		return rawJSON
	}
	mapped := state.mapFingerprintValue(kind, original)
	if mapped == "" {
		return rawJSON
	}
	rawJSON, _ = sjson.SetBytes(rawJSON, path, mapped)
	state.recordFingerprintReplacement(kind, current, mapped)
	return rawJSON
}

func applyCodexFingerprintHeaders(headers http.Header, state *codexIdentityConfuseState) {
	if headers == nil || state == nil || state.fingerprintMode == codexFingerprintModeOff {
		return
	}
	rewriteCodexFingerprintHeader(headers, state, "installation", "X-Codex-Installation-Id")
	if raw := headerValueCaseInsensitive(headers, "X-Codex-Turn-Metadata"); raw != "" {
		setHeaderCasePreserved(headers, "X-Codex-Turn-Metadata", rewriteCodexFingerprintTurnMetadata("", raw, state))
	}
	if state.fingerprintMode < codexFingerprintModeSession {
		return
	}
	if sessionID := codexSessionHeaderValue(headers); sessionID != "" {
		mapped := state.mapFingerprintHeaderValue("session", sessionID)
		setCodexSessionHeaderCasePreserved(headers, "Session-Id", mapped)
		state.recordFingerprintReplacement("session", sessionID, mapped)
	}
	for _, key := range []string{"Conversation_id", "Conversation-Id"} {
		rewriteCodexFingerprintHeader(headers, state, "session", key)
	}
	if state.fingerprintMode < codexFingerprintModeFull {
		return
	}
	for _, identity := range []struct {
		kind string
		key  string
	}{
		{kind: "thread", key: "Thread-Id"},
		{kind: "thread", key: "X-Codex-Parent-Thread-Id"},
		{kind: "request", key: "X-Client-Request-Id"},
		{kind: "window", key: "X-Codex-Window-Id"},
	} {
		rewriteCodexFingerprintHeader(headers, state, identity.kind, identity.key)
	}
}

func rewriteCodexFingerprintHeader(headers http.Header, state *codexIdentityConfuseState, kind, key string) {
	original := headerValueCaseInsensitive(headers, key)
	if original == "" {
		return
	}
	mapped := state.mapFingerprintHeaderValue(kind, original)
	setHeaderCasePreserved(headers, key, mapped)
	state.recordFingerprintReplacement(kind, original, mapped)
}

func applyCodexFingerprintResponsePayload(payload []byte, state codexIdentityConfuseState, exposeClient bool) []byte {
	if state.fingerprintMode == codexFingerprintModeOff || !exposeClient {
		return payload
	}
	for _, replacement := range state.fingerprintReplacements {
		payload = replaceCodexIdentityResponsePayload(payload, replacement.mapped, replacement.original)
	}
	return payload
}

func (state *codexIdentityConfuseState) mapFingerprintHeaderValue(kind, value string) string {
	if state == nil {
		return strings.TrimSpace(value)
	}
	if mapped := state.existingFingerprintMapping(kind, value); mapped != "" {
		return mapped
	}
	if state.fingerprintMode == codexFingerprintModeFull && kind == "session" {
		if mapped := state.existingFingerprintMapping("cache", value); mapped != "" {
			return mapped
		}
	}
	return state.mapFingerprintValue(kind, value)
}

func (state *codexIdentityConfuseState) mapFingerprintValue(kind, value string) string {
	value = strings.TrimSpace(value)
	if state == nil || state.fingerprintMode == codexFingerprintModeOff || state.fingerprintSeed == "" || value == "" {
		return value
	}
	for _, replacement := range state.fingerprintReplacements {
		if replacement.mapped == value {
			return value
		}
	}
	if mapped := state.existingFingerprintMapping(kind, value); mapped != "" {
		return mapped
	}
	mapped := helps.CodexFingerprintUUID(state.fingerprintSeed, kind, value)
	state.recordFingerprintReplacement(kind, value, mapped)
	return mapped
}

func (state *codexIdentityConfuseState) existingFingerprintMapping(kind, original string) string {
	if state == nil {
		return ""
	}
	original = strings.TrimSpace(original)
	for _, replacement := range state.fingerprintReplacements {
		if replacement.kind == kind && replacement.original == original {
			return replacement.mapped
		}
	}
	return ""
}

func (state *codexIdentityConfuseState) recordFingerprintReplacement(kind, original, mapped string) {
	if state == nil {
		return
	}
	kind = strings.TrimSpace(kind)
	original = strings.TrimSpace(original)
	mapped = strings.TrimSpace(mapped)
	if kind == "" || original == "" || mapped == "" || original == mapped {
		return
	}
	for _, replacement := range state.fingerprintReplacements {
		if replacement.kind == kind && replacement.original == original && replacement.mapped == mapped {
			return
		}
	}
	state.fingerprintReplacements = append(state.fingerprintReplacements, codexFingerprintReplacement{
		kind:     kind,
		original: original,
		mapped:   mapped,
	})
}

func rewriteCodexFingerprintTurnMetadata(originalRaw, currentRaw string, state *codexIdentityConfuseState) string {
	currentRaw = strings.TrimSpace(currentRaw)
	if state == nil || currentRaw == "" {
		return currentRaw
	}
	var current map[string]any
	if err := json.Unmarshal([]byte(currentRaw), &current); err != nil {
		return currentRaw
	}
	var original map[string]any
	if raw := strings.TrimSpace(originalRaw); raw != "" {
		_ = json.Unmarshal([]byte(raw), &original)
	}
	rewriteCodexFingerprintMetadataMap(original, current, state)
	encoded, err := json.Marshal(current)
	if err != nil {
		return currentRaw
	}
	return string(encoded)
}

func rewriteCodexFingerprintMetadataMap(original map[string]any, current map[string]any, state *codexIdentityConfuseState) {
	for key, value := range current {
		originalValue := any(nil)
		if original != nil {
			originalValue = original[key]
		}
		switch typed := value.(type) {
		case string:
			kind := codexFingerprintMetadataKind(state.fingerprintMode, key)
			if kind == "" {
				continue
			}
			originalString, _ := originalValue.(string)
			originalString = strings.TrimSpace(originalString)
			if originalString == "" {
				originalString = typed
			}
			mapped := state.mapFingerprintValue(kind, originalString)
			current[key] = mapped
			state.recordFingerprintReplacement(kind, typed, mapped)
		case map[string]any:
			originalChild, _ := originalValue.(map[string]any)
			rewriteCodexFingerprintMetadataMap(originalChild, typed, state)
		case []any:
			originalItems, _ := originalValue.([]any)
			for index, item := range typed {
				child, ok := item.(map[string]any)
				if !ok {
					continue
				}
				var originalChild map[string]any
				if index < len(originalItems) {
					originalChild, _ = originalItems[index].(map[string]any)
				}
				rewriteCodexFingerprintMetadataMap(originalChild, child, state)
			}
		}
	}
}

func codexFingerprintMetadataKind(mode codexFingerprintMode, key string) string {
	normalized := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(key)), "-", "_")
	switch normalized {
	case "installation_id", "x_codex_installation_id":
		return "installation"
	case "session_id", "conversation_id":
		if mode >= codexFingerprintModeSession {
			return "session"
		}
	case "prompt_cache_key":
		if mode >= codexFingerprintModeFull {
			return "cache"
		}
	case "thread_id", "parent_thread_id", "forked_from_thread_id", "forked_from_id", "root_thread_id", "x_codex_parent_thread_id":
		if mode >= codexFingerprintModeFull {
			return "thread"
		}
	case "turn_id", "parent_turn_id", "root_turn_id":
		if mode >= codexFingerprintModeFull {
			return "turn"
		}
	case "window_id", "x_codex_window_id":
		if mode >= codexFingerprintModeFull {
			return "window"
		}
	case "request_id", "client_request_id", "x_client_request_id":
		if mode >= codexFingerprintModeFull {
			return "request"
		}
	}
	return ""
}

func codexFingerprintTurnMetadata(payload []byte) string {
	return strings.TrimSpace(gjson.GetBytes(payload, "client_metadata.x-codex-turn-metadata").String())
}
