package handlers

import (
	"context"
	"testing"

	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// A stream channel that is closed while the request context is canceled was cut by the cancellation: the shared select picks at
// random when both are ready, and the plain close ended the request as a success. The cancellation wins every time; a close on a
// live context is still the end of the stream.
func TestNextStreamChunkReportsCancellationWhenTheChannelClosesWithIt(t *testing.T) {
	for range 200 {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		chunks := make(chan coreexecutor.StreamChunk)
		close(chunks)
		if _, ok, canceled := nextStreamChunk(ctx, nil, nil, chunks); ok || !canceled {
			t.Fatalf("closed channel on a canceled context: ok=%v canceled=%v, want a cancellation", ok, canceled)
		}
	}
	chunks := make(chan coreexecutor.StreamChunk)
	close(chunks)
	if _, ok, canceled := nextStreamChunk(context.Background(), nil, nil, chunks); ok || canceled {
		t.Fatalf("closed channel on a live context: ok=%v canceled=%v, want the end of the stream", ok, canceled)
	}
}
