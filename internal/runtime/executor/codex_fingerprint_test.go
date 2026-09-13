package executor

import (
	"bytes"
	"context"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

func codexFingerprintTestAuth(mode string) *cliproxyauth.Auth {
	return &cliproxyauth.Auth{
		ID:       "auth-id",
		Provider: "codex",
		Metadata: map[string]any{
			"codex_fingerprint_mode": mode,
			"codex_fingerprint_seed": "card-seed",
		},
	}
}

func codexFingerprintTestPayload() []byte {
	return []byte(`{
		"prompt_cache_key":"cache-1",
		"session_id":"session-1",
		"conversation_id":"conversation-1",
		"thread_id":"thread-1",
		"turn_id":"turn-1",
		"window_id":"window-1",
		"request_id":"request-1",
		"client_metadata":{
			"x-codex-installation-id":"installation-1",
			"session_id":"session-1",
			"conversation_id":"conversation-1",
			"thread_id":"thread-1",
			"x-codex-window-id":"window-1",
			"x-client-request-id":"request-1",
			"x-codex-turn-metadata":"{\"installation_id\":\"installation-1\",\"session_id\":\"session-1\",\"conversation_id\":\"conversation-1\",\"prompt_cache_key\":\"cache-1\",\"thread_id\":\"thread-1\",\"parent_thread_id\":\"parent-1\",\"turn_id\":\"turn-1\",\"window_id\":\"window-1\",\"request_id\":\"request-1\"}"
		}
	}`)
}

func TestCodexFingerprintPolicyDefaultsToOff(t *testing.T) {
	t.Parallel()

	for _, auth := range []*cliproxyauth.Auth{
		nil,
		{ID: "auth-id"},
		{ID: "auth-id", Metadata: map[string]any{"codex_fingerprint_mode": "invalid"}},
	} {
		mode, _ := codexFingerprintPolicy(auth)
		if mode != codexFingerprintModeOff {
			t.Fatalf("mode = %d, want off", mode)
		}
	}
}

func TestCodexFingerprintPolicyPrefersAttributesAndFallsBackToAuthID(t *testing.T) {
	t.Parallel()

	auth := &cliproxyauth.Auth{
		ID: "auth-fallback",
		Attributes: map[string]string{
			"codex-fingerprint-mode": " device ",
		},
		Metadata: map[string]any{
			"codex_fingerprint_mode": "full",
			"codex_fingerprint_seed": "",
		},
	}
	mode, seed := codexFingerprintPolicy(auth)
	if mode != codexFingerprintModeDevice {
		t.Fatalf("mode = %d, want device", mode)
	}
	if seed != "auth-fallback" {
		t.Fatalf("seed = %q, want auth-fallback", seed)
	}
}

func TestCodexFingerprintModeBoundaries(t *testing.T) {
	t.Parallel()

	payload := codexFingerprintTestPayload()
	tests := []struct {
		name              string
		mode              string
		installationMoves bool
		sessionMoves      bool
		fullMoves         bool
	}{
		{name: "off", mode: "off"},
		{name: "device", mode: "device", installationMoves: true},
		{name: "session", mode: "session", installationMoves: true, sessionMoves: true},
		{name: "full", mode: "full", installationMoves: true, sessionMoves: true, fullMoves: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			body, _ := applyCodexFingerprintBody(codexFingerprintTestAuth(test.mode), payload, payload, codexIdentityConfuseState{})
			metadata := gjson.GetBytes(body, "client_metadata.x-codex-turn-metadata").String()

			assertCodexFingerprintMoved(t, gjson.GetBytes(body, "client_metadata.x-codex-installation-id").String(), "installation-1", test.installationMoves)
			assertCodexFingerprintMoved(t, gjson.Get(metadata, "installation_id").String(), "installation-1", test.installationMoves)
			for _, field := range []struct {
				got      string
				original string
			}{
				{got: gjson.GetBytes(body, "session_id").String(), original: "session-1"},
				{got: gjson.GetBytes(body, "conversation_id").String(), original: "conversation-1"},
				{got: gjson.Get(metadata, "session_id").String(), original: "session-1"},
				{got: gjson.Get(metadata, "conversation_id").String(), original: "conversation-1"},
			} {
				assertCodexFingerprintMoved(t, field.got, field.original, test.sessionMoves)
			}
			for _, field := range []struct {
				got      string
				original string
			}{
				{got: gjson.GetBytes(body, "prompt_cache_key").String(), original: "cache-1"},
				{got: gjson.GetBytes(body, "thread_id").String(), original: "thread-1"},
				{got: gjson.GetBytes(body, "turn_id").String(), original: "turn-1"},
				{got: gjson.GetBytes(body, "window_id").String(), original: "window-1"},
				{got: gjson.GetBytes(body, "request_id").String(), original: "request-1"},
				{got: gjson.Get(metadata, "prompt_cache_key").String(), original: "cache-1"},
				{got: gjson.Get(metadata, "thread_id").String(), original: "thread-1"},
				{got: gjson.Get(metadata, "parent_thread_id").String(), original: "parent-1"},
				{got: gjson.Get(metadata, "turn_id").String(), original: "turn-1"},
				{got: gjson.Get(metadata, "window_id").String(), original: "window-1"},
				{got: gjson.Get(metadata, "request_id").String(), original: "request-1"},
			} {
				assertCodexFingerprintMoved(t, field.got, field.original, test.fullMoves)
			}
		})
	}
}

func assertCodexFingerprintMoved(t *testing.T, got, original string, moved bool) {
	t.Helper()
	if moved && (got == "" || got == original) {
		t.Fatalf("value = %q, want a mapped value for %q", got, original)
	}
	if !moved && got != original {
		t.Fatalf("value = %q, want original %q", got, original)
	}
}

func TestCodexFingerprintMappingsAreStableAndIsolated(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"session_id":"shared","thread_id":"shared"}`)
	firstBody, _ := applyCodexFingerprintBody(codexFingerprintTestAuth("full"), payload, payload, codexIdentityConfuseState{})
	repeatBody, _ := applyCodexFingerprintBody(codexFingerprintTestAuth("full"), payload, payload, codexIdentityConfuseState{})
	if !bytes.Equal(firstBody, repeatBody) {
		t.Fatalf("same seed and payload produced different mappings:\n%s\n%s", firstBody, repeatBody)
	}

	otherAuth := codexFingerprintTestAuth("full")
	otherAuth.Metadata["codex_fingerprint_seed"] = "other-card"
	otherBody, _ := applyCodexFingerprintBody(otherAuth, payload, payload, codexIdentityConfuseState{})
	if bytes.Equal(firstBody, otherBody) {
		t.Fatal("different card seeds produced the same mappings")
	}

	if sessionID, threadID := gjson.GetBytes(firstBody, "session_id").String(), gjson.GetBytes(firstBody, "thread_id").String(); sessionID == threadID {
		t.Fatalf("different identity kinds reused mapping %q", sessionID)
	}

	otherSession := []byte(`{"session_id":"another-session"}`)
	otherSessionBody, _ := applyCodexFingerprintBody(codexFingerprintTestAuth("session"), otherSession, otherSession, codexIdentityConfuseState{})
	if gjson.GetBytes(firstBody, "session_id").String() == gjson.GetBytes(otherSessionBody, "session_id").String() {
		t.Fatal("different sessions produced the same mapping")
	}
}

func TestCodexFingerprintHeadersMatchBodyMappings(t *testing.T) {
	t.Parallel()

	payload := codexFingerprintTestPayload()
	body, state := applyCodexFingerprintBody(codexFingerprintTestAuth("full"), payload, payload, codexIdentityConfuseState{})
	headers := http.Header{
		"Session-Id":               {"session-1"},
		"Conversation_id":          {"conversation-1"},
		"Thread-Id":                {"thread-1"},
		"X-Codex-Installation-Id":  {"installation-1"},
		"X-Codex-Window-Id":        {"window-1"},
		"X-Codex-Parent-Thread-Id": {"parent-1"},
		"X-Client-Request-Id":      {"request-1"},
		"X-Codex-Turn-Metadata":    {gjson.GetBytes(payload, "client_metadata.x-codex-turn-metadata").String()},
	}
	applyCodexFingerprintHeaders(headers, &state)

	checks := []struct {
		header string
		body   string
	}{
		{header: "Session-Id", body: gjson.GetBytes(body, "session_id").String()},
		{header: "Conversation_id", body: gjson.GetBytes(body, "conversation_id").String()},
		{header: "Thread-Id", body: gjson.GetBytes(body, "thread_id").String()},
		{header: "X-Codex-Installation-Id", body: gjson.GetBytes(body, "client_metadata.x-codex-installation-id").String()},
		{header: "X-Codex-Window-Id", body: gjson.GetBytes(body, "client_metadata.x-codex-window-id").String()},
		{header: "X-Client-Request-Id", body: gjson.GetBytes(body, "client_metadata.x-client-request-id").String()},
	}
	for _, check := range checks {
		if got := headerValueCaseInsensitive(headers, check.header); got != check.body {
			t.Fatalf("%s = %q, want body mapping %q", check.header, got, check.body)
		}
	}
	metadata := headers.Get("X-Codex-Turn-Metadata")
	if got, want := gjson.Get(metadata, "parent_thread_id").String(), headers.Get("X-Codex-Parent-Thread-Id"); got != want {
		t.Fatalf("turn metadata parent_thread_id = %q, want header %q", got, want)
	}
}

func TestCodexFingerprintResponseRestoresClientIdentifiers(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"session_id":"shared","thread_id":"shared","request_id":"request-1"}`)
	body, state := applyCodexFingerprintBody(codexFingerprintTestAuth("full"), payload, payload, codexIdentityConfuseState{})
	if bytes.Contains(body, []byte(`"shared"`)) {
		t.Fatalf("upstream body retained original identifiers: %s", body)
	}
	restored := applyCodexIdentityExposeResponsePayload(body, state)
	if !bytes.Equal(restored, payload) {
		t.Fatalf("restored response = %s, want %s", restored, payload)
	}
}

func TestCodexFingerprintDoesNotRewriteUnchangedResponseFields(t *testing.T) {
	t.Parallel()

	auth := codexFingerprintTestAuth("session")
	payload := []byte(`{"prompt_cache_key":"cache-1"}`)
	_, state := applyCodexFingerprintBody(auth, payload, payload, codexIdentityConfuseState{})
	headers := http.Header{"Session-Id": {"cache-1"}}
	applyCodexFingerprintHeaders(headers, &state)

	if upstream := applyCodexIdentityConfuseResponsePayload(payload, state); !bytes.Equal(upstream, payload) {
		t.Fatalf("unchanged prompt_cache_key was rewritten in upstream response: %s", upstream)
	}
}

func TestCodexFingerprintComposesWithIdentityConfuse(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Routing: config.RoutingConfig{SessionAffinity: true},
		Codex:   config.CodexConfig{IdentityConfuse: true},
	}
	auth := codexFingerprintTestAuth("full")
	payload := []byte(`{"prompt_cache_key":"cache-1","client_metadata":{"x-codex-installation-id":"installation-1","x-codex-turn-metadata":"{\"turn_id\":\"turn-1\"}"}}`)

	body, state := applyCodexIdentityConfuseBody(cfg, auth, payload, payload)
	body, state = applyCodexFingerprintBody(auth, payload, body, state)
	if got, want := gjson.GetBytes(body, "prompt_cache_key").String(), helps.CodexFingerprintUUID("card-seed", "cache", "cache-1"); got != want {
		t.Fatalf("prompt_cache_key = %q, want %q", got, want)
	}
	restored := applyCodexIdentityExposeResponsePayload(body, state)
	if got := gjson.GetBytes(restored, "prompt_cache_key").String(); got != "cache-1" {
		t.Fatalf("restored prompt_cache_key = %q, want cache-1", got)
	}
	metadata := gjson.GetBytes(restored, "client_metadata.x-codex-turn-metadata").String()
	if got := gjson.Get(metadata, "turn_id").String(); got != "turn-1" {
		t.Fatalf("restored turn_id = %q, want turn-1", got)
	}
}

func TestCodexWebsocketFingerprintUsesFullCacheMapping(t *testing.T) {
	t.Parallel()

	auth := codexFingerprintTestAuth("full")
	req := cliproxyexecutor.Request{
		Model:   "gpt-5-codex",
		Payload: []byte(`{"prompt_cache_key":"cache-ws"}`),
	}
	body, headers := applyCodexPromptCacheHeaders(sdktranslator.FormatOpenAIResponse, req, []byte(`{"model":"gpt-5-codex"}`))
	body, state := applyCodexFingerprintBody(auth, req.Payload, body, codexIdentityConfuseState{})
	headers = applyCodexWebsocketHeaders(context.Background(), headers, auth, "oauth-token", &config.Config{})
	applyCodexFingerprintHeaders(headers, &state)

	mappedCache := gjson.GetBytes(body, "prompt_cache_key").String()
	if got := codexSessionHeaderValue(headers); got != mappedCache {
		t.Fatalf("websocket session = %q, want mapped cache %q", got, mappedCache)
	}
	if got := headers.Get("Conversation_id"); got != mappedCache {
		t.Fatalf("websocket conversation = %q, want mapped cache %q", got, mappedCache)
	}
}
