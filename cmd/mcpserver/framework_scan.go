package mcpserver

import (
	"context"
	"fmt"

	"github.com/kubescape/kubescape/v3/core/cautils"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
)

// RunFrameworkScan executes a headless, highly-optimized on-demand scan using the Kubescape engine,
// isolated to just the given framework (e.g. nsa, mitre) to ensure rapid return times for MCP.
func (ksServer *KubescapeMcpserver) RunFrameworkScan(ctx context.Context, namespace string, frameworkName string) ([]byte, error) {
	if frameworkName == "allcontrols" {
		return nil, fmt.Errorf("the 'allcontrols' framework is exceptionally heavy and is not supported in the headless MCP scanner")
	}
	policyIdentifiers := []cautils.PolicyIdentifier{
		{Kind: apisv1.KindFramework, Identifier: frameworkName},
	}
	return runScan(ctx, ksServer, namespace, policyIdentifiers, "Framework", true)
}
