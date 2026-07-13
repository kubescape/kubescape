package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	"github.com/kubescape/kubescape/v3/core/pkg/opaprocessor"
	"github.com/kubescape/kubescape/v3/core/pkg/policyhandler"
	"github.com/kubescape/kubescape/v3/core/pkg/resourcehandler"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/resources"
)

// RunRBACScan executes a headless, highly-optimized on-demand scan using the Kubescape engine,
// isolated to just the core RBAC controls (e.g. C-0015, C-0016) to ensure rapid return times for MCP.
func (ksServer *KubescapeMcpserver) RunRBACScan(ctx context.Context, namespace string) ([]byte, error) {
	logger.L().Ctx(ctx).Info("Initiating on-demand MCP RBAC security scan", helpers.String("namespace", namespace))

	// 1. Initialize custom ScanInfo isolated to RBAC controls to guarantee speed
	scanInfo := &cautils.ScanInfo{
		Getters: cautils.Getters{
			PolicyGetter:         ksServer.policyGetter,
			ExceptionsGetter:     ksServer.policyGetter,
			ControlsInputsGetter: ksServer.policyGetter,
			AttackTracksGetter:   ksServer.policyGetter,
		},
		ScanAll: false,
		PolicyIdentifier: []cautils.PolicyIdentifier{
			{Kind: apisv1.KindControl, Identifier: "C-0015"}, // Over-permissive RBAC
			{Kind: apisv1.KindControl, Identifier: "C-0016"}, // Cluster-admin bindings
		},
		IncludeNamespaces: namespace,
		ScanTimeout:       10 * time.Second, // Fallback timeout
	}

	// 2. Fetch the specific Policies
	scanCtx, cancel := context.WithTimeout(ctx, scanInfo.ScanTimeout)
	defer cancel()

	policyHandler := policyhandler.NewRequestScopedPolicyHandler("")
	scanData, err := policyHandler.CollectPolicies(scanCtx, scanInfo.PolicyIdentifier, scanInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to collect RBAC policies: %w", err)
	}

	// 3. Pull required K8s resources (only pulls resources defined by C-0015 and C-0016)
	k8sHandler := resourcehandler.NewK8sResourceHandler(scanCtx, k8sinterface.NewKubernetesApi(), nil, nil, "")
	if err := resourcehandler.CollectResources(scanCtx, k8sHandler, scanData, scanInfo); err != nil {
		return nil, fmt.Errorf("failed to collect RBAC resources: %w", err)
	}

	// 4. Run the core OPA Processor engine
	deps := resources.NewRegoDependenciesData(k8sinterface.GetK8sConfig(), "")
	opap := opaprocessor.NewOPAProcessor(scanData, deps, "", scanInfo.ExcludedNamespaces, scanInfo.IncludeNamespaces, false, nil)

	// Execute the evaluation logic
	if err := opap.ProcessRulesListener(scanCtx, cautils.NewProgressHandler("")); err != nil {
		return nil, fmt.Errorf("failed to process RBAC rules: %w", err)
	}

	// 5. Aggregate results (Failed Resources)
	// For MCP, we only care about the failed bindings/roles to send to the AI
	var failedResources []interface{}
	for _, result := range scanData.ResourcesResult {
		if result.GetStatus(nil).IsFailed() {
			failedResources = append(failedResources, result)
		}
	}

	logger.L().Ctx(ctx).Info("Completed on-demand MCP RBAC security scan", helpers.Int("failed_resources", len(failedResources)))

	responseJSON, err := json.MarshalIndent(failedResources, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal RBAC scan results: %w", err)
	}

	return responseJSON, nil
}
