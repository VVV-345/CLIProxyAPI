package auth

import (
	"context"
	"net/http"
	"testing"
	"time"
)

type streamTruncatedStatusError struct {
	msg string
}

func (e *streamTruncatedStatusError) Error() string           { return e.msg }
func (e *streamTruncatedStatusError) StatusCode() int         { return http.StatusBadGateway }
func (e *streamTruncatedStatusError) IsStreamTruncated() bool { return true }

func TestManager_MarkResult_StreamTruncatedDoesNotCooldownOrRotate(t *testing.T) {
	withQuotaCooldownEnabled(t)
	prevTransient := transientErrorCooldownSeconds.Load()
	SetTransientErrorCooldownSeconds(60)
	t.Cleanup(func() { transientErrorCooldownSeconds.Store(prevTransient) })

	errTruncated := &streamTruncatedStatusError{msg: "upstream stream closed before finishReason"}
	if !isRequestInvalidError(errTruncated) {
		t.Fatal("stream_truncated must stop credential rotation")
	}
	resultErr := resultErrorFromError(errTruncated)
	if resultErr == nil || resultErr.Code != ErrorCodeStreamTruncated {
		t.Fatalf("result error = %#v, want code %s", resultErr, ErrorCodeStreamTruncated)
	}
	if !shouldSkipCredentialCooldown(resultErr) {
		t.Fatalf("shouldSkipCredentialCooldown(%#v) = false", resultErr)
	}

	manager := NewManager(nil, nil, nil)
	auth := &Auth{ID: "auth-stream-truncated", Provider: "gemini", Status: StatusActive}
	if _, errRegister := manager.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("Register returned error: %v", errRegister)
	}
	model := "gemini-4-argon"
	manager.MarkResult(context.Background(), Result{
		AuthID:   auth.ID,
		Provider: auth.Provider,
		Model:    model,
		Success:  false,
		Error:    resultErr,
	})
	assertNoCooldown(t, manager, auth.ID, model)

	wait, retry := manager.shouldRetryAfterError(errTruncated, 0, []string{"gemini"}, model, time.Minute)
	if retry || wait != 0 {
		t.Fatalf("stream_truncated retry = (%v, %v), want (0, false)", wait, retry)
	}
}
