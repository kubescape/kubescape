package gvisor

import (
	"context"
	"fmt"
)

// TraceIngester defines the pipeline for reading runsc trace events
type TraceIngester struct {
	traceSocket string
}

// NewTraceIngester creates a new TraceIngester
func NewTraceIngester(socket string) *TraceIngester {
	return &TraceIngester{
		traceSocket: socket,
	}
}

// Start begins listening to the gVisor runsc trace events
func (t *TraceIngester) Start(ctx context.Context) error {
	fmt.Println("Starting gVisor runsc trace ingestion pipeline...")
	// Dummy logic to simulate ingestion
	<-ctx.Done()
	return nil
}
