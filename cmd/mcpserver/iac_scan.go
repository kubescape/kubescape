package mcpserver

import (
	"context"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resourcehandler"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
)

// runIaCScan executes a scan against local Infrastructure-as-Code files using the FileResourceHandler.
func (ksServer *KubescapeMcpserver) runIaCScan(ctx context.Context, path string, frameworkName string) ([]byte, error) {
	if frameworkName == "" {
		frameworkName = "allcontrols" // user mentioned safe default
	}

	policyIdentifiers := []cautils.PolicyIdentifier{
		{Kind: apisv1.KindFramework, Identifier: frameworkName},
	}

	fileHandler := resourcehandler.NewFileResourceHandler()

	return runScan(ctx, ksServer, "", policyIdentifiers, "Local IaC", true, fileHandler, []string{path})
}
