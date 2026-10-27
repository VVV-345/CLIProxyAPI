package auth

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestManager_StaleInFlightSuccessDoesNotClearCooldown(t *testing.T) {
	withQuotaCooldownEnabled(t)

	manager := NewManager(nil, nil, nil)
	auth := &Auth{ID: "auth-stale-success", Provider: "gemini", Status: StatusActive}
	if _, errRegister := manager.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("Register returned error: %v", errRegister)
	}

	staleSeq := manager.nextExecutionSeq()
	laterSeq := manager.nextExecutionSeq()
	ctx := context.Background()
	manager.MarkResult(ctx, Result{
		AuthID:       auth.ID,
		Provider:     auth.Provider,
		Model:        "gemini-4-argon",
		Success:      false,
		ExecutionSeq: laterSeq,
		Error:        &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota", Retryable: true},
	})

	cooled, ok := manager.GetByID(auth.ID)
	if !ok || cooled == nil || cooled.ModelStates["gemini-4-argon"] == nil || !cooled.ModelStates["gemini-4-argon"].Unavailable {
		t.Fatalf("expected cooldown after quota failure: %+v", cooled)
	}
	deadline := cooled.ModelStates["gemini-4-argon"].NextRetryAfter

	manager.MarkResult(ctx, Result{
		AuthID:       auth.ID,
		Provider:     auth.Provider,
		Model:        "gemini-4-argon",
		Success:      true,
		ExecutionSeq: staleSeq,
	})
	retained, _ := manager.GetByID(auth.ID)
	state := retained.ModelStates["gemini-4-argon"]
	if state == nil || !state.Unavailable || !state.NextRetryAfter.Equal(deadline) {
		t.Fatalf("stale success cleared cooldown: %+v", state)
	}

	manager.MarkResult(ctx, Result{
		AuthID:       auth.ID,
		Provider:     auth.Provider,
		Model:        "gemini-4-argon",
		Success:      true,
		ExecutionSeq: manager.nextExecutionSeq(),
	})
	cleared, _ := manager.GetByID(auth.ID)
	state = cleared.ModelStates["gemini-4-argon"]
	if state == nil || state.Unavailable || !state.NextRetryAfter.IsZero() {
		t.Fatalf("later success did not clear cooldown: %+v", state)
	}
	if time.Since(deadline) > 0 && deadline.Before(time.Now().Add(-time.Hour)) {
		t.Fatalf("unexpected deadline %v", deadline)
	}
}
