package mcpserver

import (
	"context"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	"github.com/kubescape/kubescape/v3/core/pkg/resourcehandler"
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

	localPolicyGetter := getter.NewLoadPolicy([]string{getter.DefaultLocalStore})
	customGetters := &cautils.Getters{
		PolicyGetter:         localPolicyGetter,
		ExceptionsGetter:     localPolicyGetter,
		ControlsInputsGetter: localPolicyGetter,
		AttackTracksGetter:   localPolicyGetter,
	}

	return runScan(ctx, ksServer, "", policyIdentifiers, "Local IaC", true, fileHandler, []string{path}, customGetters)
}
