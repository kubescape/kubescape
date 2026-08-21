package gvisor

import (
	"context"

	"github.com/kubescape/go-logger"
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

// Start is a scaffold method that currently blocks until the context is canceled.
// It does not yet implement actual runsc trace ingestion using the trace socket.
func (t *TraceIngester) Start(ctx context.Context) error {
	logger.L().Info("Starting gVisor runsc trace ingestion pipeline (scaffold mode)...")
	// Dummy logic to simulate ingestion
	<-ctx.Done()
	return nil
}
