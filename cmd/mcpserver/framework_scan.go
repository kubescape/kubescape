package mcpserver

import (
	"context"
)

// RunFrameworkScan executes a headless, highly-optimized on-demand scan using the Kubescape engine,
// isolated to just the given framework (e.g. nsa, mitre) to ensure rapid return times for MCP.
func (ksServer *KubescapeMcpserver) RunFrameworkScan(ctx context.Context, namespace string, frameworkName string) ([]byte, error) {
	return runFrameworkScan(ctx, ksServer, namespace, []string{frameworkName}, "Framework")
}
