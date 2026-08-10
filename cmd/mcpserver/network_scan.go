package mcpserver

import (
	"context"
)

// RunNetworkScan executes a headless, highly-optimized on-demand scan using the Kubescape engine,
// isolated to just the core Network controls (e.g. C-0030) to ensure rapid return times for MCP.
func (ksServer *KubescapeMcpserver) RunNetworkScan(ctx context.Context, namespace string) ([]byte, error) {
	return runControlScan(ctx, ksServer, namespace, []string{"C-0030"}, "Network")
}
