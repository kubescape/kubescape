package mcpserver

import (
	"context"
)

// RunRBACScan executes a headless, highly-optimized on-demand scan using the Kubescape engine,
// isolated to just the core RBAC controls (e.g. C-0015, C-0016) to ensure rapid return times for MCP.
func (ksServer *KubescapeMcpserver) RunRBACScan(ctx context.Context, namespace string) ([]byte, error) {
	return runControlScan(ctx, ksServer, namespace, []string{"C-0015", "C-0016"}, "RBAC")
}
