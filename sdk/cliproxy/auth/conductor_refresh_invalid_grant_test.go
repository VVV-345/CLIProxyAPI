package auth

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type invalidGrantRefreshExecutor struct {
	id           string
	refreshCalls atomic.Int32
	errToReturn  error
}

func (e *invalidGrantRefreshExecutor) Identifier() string { return e.id }

func (e *invalidGrantRefreshExecutor) Execute(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *invalidGrantRefreshExecutor) ExecuteStream(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}

func (e *invalidGrantRefreshExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	e.refreshCalls.Add(1)
	if e.errToReturn != nil {
		return nil, e.errToReturn
	}
	return auth, nil
}

func (e *invalidGrantRefreshExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *invalidGrantRefreshExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

type invalidGrantStatusError struct {
	code int
	msg  string
}

func (e invalidGrantStatusError) Error() string   { return fmt.Sprintf("status %d: %s", e.code, e.msg) }
func (e invalidGrantStatusError) StatusCode() int { return e.code }

func TestNextRefreshCheckAt_DisabledInvalidGrantUnscheduled(t *testing.T) {
	now := time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)
	auth := &Auth{
		ID:       "invalid-grant-disabled",
		Provider: "claude",
		Disabled: true,
		Status:   StatusDisabled,
		LastError: &Error{
			HTTPStatus: http.StatusBadRequest,
			Message:    `{"error":"invalid_grant"}`,
		},
		Metadata: map[string]any{"expires_at": now.Add(time.Hour).Format(time.RFC3339)},
	}
	if _, ok := nextRefreshCheckAt(now, auth, 15*time.Minute); ok {
		t.Fatal("disabled invalid_grant credential must not be scheduled for refresh")
	}
}

func TestRefreshAuthForRequest_DisabledInvalidGrantDoesNotRefresh(t *testing.T) {
	ctx := context.Background()
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	executor := &invalidGrantRefreshExecutor{id: "claude"}
	manager.RegisterExecutor(executor)

	auth := &Auth{
		ID:       "disabled-invalid-grant",
		Provider: "claude",
		Disabled: true,
		Status:   StatusDisabled,
		LastError: &Error{
			HTTPStatus: http.StatusBadRequest,
			Message:    "invalid_grant",
		},
		Metadata: map[string]any{"refresh_token": "refresh-1"},
	}
	if _, errRegister := manager.Register(ctx, auth); errRegister != nil {
		t.Fatalf("Register error: %v", errRegister)
	}
	if _, errRefresh := manager.refreshAuthForRequest(ctx, auth.ID, ""); errRefresh == nil {
		t.Fatal("expected refresh to stop for disabled invalid_grant")
	}
	if executor.refreshCalls.Load() != 0 {
		t.Fatalf("refresh calls = %d, want 0", executor.refreshCalls.Load())
	}
}

func TestRefreshAuthForRequest_EnabledInvalidGrantUsesExponentialBackoff(t *testing.T) {
	ctx := context.Background()
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	executor := &invalidGrantRefreshExecutor{
		id:          "claude",
		errToReturn: invalidGrantStatusError{code: http.StatusBadRequest, msg: "invalid_grant"},
	}
	manager.RegisterExecutor(executor)

	auth := &Auth{
		ID:       "enabled-invalid-grant",
		Provider: "claude",
		Status:   StatusActive,
		Metadata: map[string]any{"refresh_token": "refresh-1"},
	}
	if _, errRegister := manager.Register(ctx, auth); errRegister != nil {
		t.Fatalf("Register error: %v", errRegister)
	}

	before := time.Now()
	if _, errRefresh := manager.refreshAuthForRequest(ctx, auth.ID, ""); errRefresh == nil {
		t.Fatal("expected invalid_grant refresh error")
	}
	updated, ok := manager.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatal("missing auth")
	}
	if updated.RefreshFailures != 1 {
		t.Fatalf("RefreshFailures = %d, want 1", updated.RefreshFailures)
	}
	if updated.NextRefreshAfter.Before(before.Add(invalidGrantBackoffBase)) || updated.NextRefreshAfter.After(before.Add(invalidGrantBackoffBase+time.Second)) {
		t.Fatalf("NextRefreshAfter = %v, want about %v after %v", updated.NextRefreshAfter, invalidGrantBackoffBase, before)
	}
	if executor.refreshCalls.Load() != 1 {
		t.Fatalf("refresh calls = %d, want 1", executor.refreshCalls.Load())
	}
}
