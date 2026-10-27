package helps

import (
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestParseClaudeRateLimitResetForError_ShortRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 17, 14, 0, 0, 0, time.UTC)
	body := []byte(`{"type":"error","error":{"type":"rate_limit_error","message":"This request would exceed the requests per minute rate limit. Please try again later."}}`)
	headers := http.Header{}
	headers.Set("Retry-After", "30")
	headers.Set("Anthropic-Ratelimit-Unified-Reset", strconv.FormatInt(now.Add(4*time.Hour).Unix(), 10))

	got := ParseClaudeRateLimitResetForError(headers, body, now)
	if got == nil {
		t.Fatal("expected short cooldown, got nil")
	}
	if *got < 31*time.Second || *got > 60*time.Second {
		t.Fatalf("cooldown = %v, want between 31s and 60s", *got)
	}

	conservative := ParseClaudeRateLimitResetForError(headers, nil, now)
	if conservative == nil || *conservative < 4*time.Hour {
		t.Fatalf("nil body cooldown = %v, want the conservative unified reset", conservative)
	}
}
