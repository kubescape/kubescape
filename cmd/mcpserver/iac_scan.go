package mcpserver

import (
	"context"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resourcehandler"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
)

// runIaCScan executes a scan against local Infrastructure-as-Code files using the FileResourceHandler.
func (ksServer *KubescapeMcpserver) runIaCScan(ctx context.Context, path string, frameworkName string) ([]byte, error) {
	if frameworkName == "" {
		frameworkName = "nsa" // default to nsa as allcontrols is too heavy
	}

	policyIdentifiers := []cautils.PolicyIdentifier{
		{Kind: apisv1.KindFramework, Identifier: frameworkName},
	}

	fileHandler := resourcehandler.NewFileResourceHandler()

	return runScan(ctx, ksServer, scanRequest{
		policyIdentifiers:   policyIdentifiers,
		label:               "Local IaC",
		wantComplianceScore: true,
		rsrcHandler:         fileHandler,
		inputPatterns:       []string{path},
	})
}
