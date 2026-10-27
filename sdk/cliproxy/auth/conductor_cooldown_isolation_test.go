package auth

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestManager_MarkResult_CredentialScopeDoesNotInheritModelQuotaDeadline(t *testing.T) {
	withQuotaCooldownEnabled(t)

	manager := NewManager(nil, nil, nil)
	auth := &Auth{ID: "auth-quota-isolation", Provider: "claude", Status: StatusActive}
	if _, errRegister := manager.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("Register returned error: %v", errRegister)
	}

	ctx := context.Background()
	before := time.Now()
	modelOnlyRetry := 8 * 24 * time.Hour
	manager.MarkResult(ctx, Result{
		AuthID:     auth.ID,
		Provider:   auth.Provider,
		Model:      "claude-fable-5-1",
		RetryAfter: &modelOnlyRetry,
		Error:      &Error{HTTPStatus: http.StatusTooManyRequests, Message: "model quota"},
	})

	modelOnly, ok := manager.GetByID(auth.ID)
	if !ok || modelOnly == nil {
		t.Fatal("missing auth after model-only quota")
	}
	fable := modelOnly.ModelStates["claude-fable-5-1"]
	if fable == nil || !fable.Unavailable || !fable.NextRetryAfter.After(before.Add(7*24*time.Hour)) {
		t.Fatalf("model-only cooldown missing: %+v", fable)
	}
	if sibling := modelOnly.ModelStates["claude-opus-5-5"]; sibling != nil && sibling.Unavailable {
		t.Fatalf("model-only 429 cooled an unrelated model: %+v", sibling)
	}

	credentialRetry := 3 * time.Hour
	manager.MarkResult(ctx, Result{
		AuthID:          auth.ID,
		Provider:        auth.Provider,
		Model:           "claude-sonnet-5",
		RetryAfter:      &credentialRetry,
		CredentialScope: true,
		Error:           &Error{HTTPStatus: http.StatusTooManyRequests, Message: "shared window rejected"},
	})

	updated, _ := manager.GetByID(auth.ID)
	minCredentialDeadline := before.Add(credentialRetry - time.Hour)
	maxCredentialDeadline := before.Add(credentialRetry + time.Hour)
	if updated.Quota.Reason != "credential_quota" ||
		updated.Quota.NextRecoverAt.Before(minCredentialDeadline) ||
		updated.Quota.NextRecoverAt.After(maxCredentialDeadline) {
		t.Fatalf("credential cooldown inherited a model-only deadline: reason=%q deadline=%v (in %v)",
			updated.Quota.Reason, updated.Quota.NextRecoverAt, updated.Quota.NextRecoverAt.Sub(before))
	}
	if fable = updated.ModelStates["claude-fable-5-1"]; fable == nil || !fable.NextRetryAfter.After(before.Add(7*24*time.Hour)) {
		t.Fatalf("model-only cooldown was not retained for Fable: %+v", fable)
	}
}

func TestManager_MarkResult_CredentialScopeBackoffDoesNotInheritModelLevel(t *testing.T) {
	withQuotaCooldownEnabled(t)

	manager := NewManager(nil, nil, nil)
	auth := &Auth{ID: "auth-quota-backoff", Provider: "claude", Status: StatusActive}
	if _, errRegister := manager.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("Register returned error: %v", errRegister)
	}

	ctx := context.Background()
	manager.MarkResult(ctx, Result{
		AuthID:   auth.ID,
		Provider: auth.Provider,
		Model:    "model-a",
		Error:    &Error{HTTPStatus: http.StatusTooManyRequests, Message: "model-only quota exceeded"},
	})
	modelOnly, _ := manager.GetByID(auth.ID)
	modelState := existingModelState(modelOnly, canonicalModelKey("model-a"))
	if modelState == nil || modelState.Quota.BackoffLevel != 1 {
		t.Fatalf("precondition failed: model backoff = %+v", modelState)
	}

	started := time.Now()
	manager.MarkResult(ctx, Result{
		AuthID:          auth.ID,
		Provider:        auth.Provider,
		Model:           "model-a",
		CredentialScope: true,
		Error:           &Error{HTTPStatus: http.StatusTooManyRequests, Message: "credential quota exceeded"},
	})
	updated, _ := manager.GetByID(auth.ID)
	if updated.Quota.BackoffLevel != 1 {
		t.Fatalf("credential cooldown inherited model backoff: got level %d, want 1", updated.Quota.BackoffLevel)
	}
	if updated.Quota.NextRecoverAt.Before(started.Add(quotaBackoffBase)) || updated.Quota.NextRecoverAt.After(time.Now().Add(quotaBackoffBase)) {
		t.Fatalf("credential cooldown deadline=%v, want about %v after %v", updated.Quota.NextRecoverAt, quotaBackoffBase, started)
	}
}
