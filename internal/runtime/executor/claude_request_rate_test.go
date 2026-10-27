package executor

import (
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestClaudePerMinuteRateLimitHonorsShortRetryAfter(t *testing.T) {
	headers := http.Header{}
	headers.Set("Retry-After", "30")
	headers.Set("Anthropic-Ratelimit-Unified-Reset", strconv.FormatInt(time.Now().Add(4*time.Hour).Unix(), 10))
	body := []byte(`{"type":"error","error":{"type":"rate_limit_error","message":"This request would exceed the requests per minute rate limit. Please try again later."}}`)

	errClassify := classifyClaudeUpstreamError(http.StatusTooManyRequests, headers, body)
	var rap retryAfterProvider
	if !errors.As(errClassify, &rap) || rap == nil || rap.RetryAfter() == nil {
		t.Fatalf("expected RetryAfter, got %v", errClassify)
	}
	got := *rap.RetryAfter()
	if got < 29*time.Second || got > 60*time.Second {
		t.Fatalf("RetryAfter = %v, want between 29s and 60s", got)
	}
}
