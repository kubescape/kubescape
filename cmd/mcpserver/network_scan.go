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
	"github.com/kubescape/kubescape/v3/core/pkg/opaprocessor"
	"github.com/kubescape/kubescape/v3/core/pkg/policyhandler"
	"github.com/kubescape/kubescape/v3/core/pkg/resourcehandler"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/resources"
)

// maxFailedNetworkResources caps the number of failed resources returned in one MCP response
// to keep the payload bounded for the AI agent.
const maxFailedNetworkResources = 100

// RunNetworkScan executes a headless, highly-optimized on-demand scan using the Kubescape engine,
// isolated to just the core Network controls (e.g. C-0030) to ensure rapid return times for MCP.
func (ksServer *KubescapeMcpserver) RunNetworkScan(ctx context.Context, namespace string) ([]byte, error) {
	logger.L().Ctx(ctx).Info("Initiating on-demand MCP Network security scan", helpers.String("namespace", namespace))

	if !k8sinterface.IsConnectedToCluster() {
		return nil, fmt.Errorf("no reachable kubernetes cluster: ensure KUBECONFIG is set or the server is running inside a cluster")
	}

	// Route all access through getK8sClient to ensure synchronized init.
	client := ksServer.getK8sClient()

	// 1. Initialize custom ScanInfo isolated to Network controls to guarantee speed
	scanInfo := &cautils.ScanInfo{
		Getters: cautils.Getters{
			PolicyGetter:         ksServer.policyGetter,
			ExceptionsGetter:     ksServer.policyGetter,
			ControlsInputsGetter: ksServer.policyGetter,
			AttackTracksGetter:   ksServer.policyGetter,
		},
		ScanAll: false,
		PolicyIdentifier: []cautils.PolicyIdentifier{
			{Kind: apisv1.KindControl, Identifier: "C-0030"}, // Ingress and Egress blocked
		},
		IncludeNamespaces: namespace,
		ScanTimeout:       10 * time.Second, // Fallback timeout
	}

	// 2. Fetch the specific Policies
	scanCtx, cancel := context.WithTimeout(ctx, scanInfo.ScanTimeout)
	defer cancel()

	policyHandler := policyhandler.NewRequestScopedPolicyHandler("")
	defer policyHandler.Close()
	scanData, err := policyHandler.CollectPolicies(scanCtx, scanInfo.PolicyIdentifier, scanInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to collect Network policies: %w", err)
	}

	// 3. Pull required K8s resources (only pulls resources defined by C-0030)
	k8sHandler := resourcehandler.NewK8sResourceHandler(scanCtx, client, nil, nil, "")
	if err := resourcehandler.CollectResources(scanCtx, k8sHandler, scanData, scanInfo); err != nil {
		return nil, fmt.Errorf("failed to collect Network resources: %w", err)
	}

	// 4. Run the core OPA Processor engine
	deps := resources.NewRegoDependenciesData(client.K8SConfig, "")
	opap := opaprocessor.NewOPAProcessor(scanData, deps, "", scanInfo.ExcludedNamespaces, scanInfo.IncludeNamespaces, false, nil)

	// Execute the evaluation logic
	if err := opap.ProcessRulesListener(scanCtx, cautils.NewProgressHandler("")); err != nil {
		return nil, fmt.Errorf("failed to process Network rules: %w", err)
	}

	// 5. Aggregate results (Failed Resources)
	var failedResources []interface{}
	totalFailed := 0
	for _, result := range scanData.ResourcesResult {
		if result.GetStatus(nil).IsFailed() {
			totalFailed++
			if len(failedResources) < maxFailedNetworkResources {
				failedResources = append(failedResources, result)
			}
		}
	}

	logger.L().Ctx(ctx).Info("Completed on-demand MCP Network security scan",
		helpers.Int("failed_resources", totalFailed),
		helpers.Int("returned_resources", len(failedResources)),
	)

	// Build response envelope
	type scanResponse struct {
		TotalFailed     int           `json:"total_failed"`
		ReturnedFailed  int           `json:"returned_failed"`
		Truncated       bool          `json:"truncated"`
		FailedResources []interface{} `json:"failed_resources"`
	}
	response := scanResponse{
		TotalFailed:     totalFailed,
		ReturnedFailed:  len(failedResources),
		Truncated:       totalFailed > maxFailedNetworkResources,
		FailedResources: failedResources,
	}

	responseJSON, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Network scan results: %w", err)
	}

	return responseJSON, nil
}
