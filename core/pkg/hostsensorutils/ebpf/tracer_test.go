package ebpf

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTracer_Start(t *testing.T) {
	tracer := NewTracer()
	assert.NotNil(t, tracer)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	events, err := tracer.Start(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, events)

	// Wait for context cancellation and channel closure
	<-ctx.Done()
	select {
	case _, ok := <-events:
		assert.False(t, ok, "channel should be closed after context done")
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for events channel to close")
	}
}
