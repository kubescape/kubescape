package ebpf

import (
	"context"
	"fmt"

	"github.com/kubescape/kubescape/v4/core/pkg/hostsensorutils"
)

type Tracer struct {
	// ebpf configuration
}

func NewTracer() *Tracer {
	return &Tracer{}
}

func (t *Tracer) Start(ctx context.Context) (<-chan hostsensorutils.SyscallEvent, error) {
	events := make(chan hostsensorutils.SyscallEvent)
	go func() {
		defer close(events)
		// Stub: Load eBPF programs, attach to tracepoints, read from perf ring buffer
		// and translate to SyscallEvent.
		fmt.Println("eBPF tracer started (stub)")
		<-ctx.Done()
	}()
	return events, nil
}
