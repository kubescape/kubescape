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

// maxFailedResources caps the number of failed resources returned in one MCP response
// to keep the payload bounded for the AI agent.
const maxFailedResources = 100

// RunRBACScan executes a headless, highly-optimized on-demand scan using the Kubescape engine,
// isolated to just the core RBAC controls (e.g. C-0015, C-0016) to ensure rapid return times for MCP.
func (ksServer *KubescapeMcpserver) RunRBACScan(ctx context.Context, namespace string) ([]byte, error) {
	logger.L().Ctx(ctx).Info("Initiating on-demand MCP RBAC security scan", helpers.String("namespace", namespace))

	// Blocker 1 & 2 fix: Guard against missing kubeconfig/cluster before calling any
	// k8sinterface functions. Both NewKubernetesApi() and GetK8sConfig() call
	// logger.L().Fatal() -> os.Exit(1) when no cluster is reachable, which would
	// terminate the entire long-lived MCP server process.
	if !k8sinterface.IsConnectedToCluster() {
		return nil, fmt.Errorf("no reachable kubernetes cluster: ensure KUBECONFIG is set or the server is running inside a cluster")
	}

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
	defer policyHandler.Close()
	scanData, err := policyHandler.CollectPolicies(scanCtx, scanInfo.PolicyIdentifier, scanInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to collect RBAC policies: %w", err)
	}

	// 3. Pull required K8s resources (only pulls resources defined by C-0015 and C-0016)
	// Reuse the cached k8sClient from the server struct to avoid per-scan re-initialization overhead.
	k8sHandler := resourcehandler.NewK8sResourceHandler(scanCtx, ksServer.k8sClient, nil, nil, "")
	if err := resourcehandler.CollectResources(scanCtx, k8sHandler, scanData, scanInfo); err != nil {
		return nil, fmt.Errorf("failed to collect RBAC resources: %w", err)
	}

	// 4. Run the core OPA Processor engine
	deps := resources.NewRegoDependenciesData(ksServer.k8sClient.K8SConfig, "")
	opap := opaprocessor.NewOPAProcessor(scanData, deps, "", scanInfo.ExcludedNamespaces, scanInfo.IncludeNamespaces, false, nil)

	// Execute the evaluation logic
	if err := opap.ProcessRulesListener(scanCtx, cautils.NewProgressHandler("")); err != nil {
		return nil, fmt.Errorf("failed to process RBAC rules: %w", err)
	}

	// 5. Aggregate results (Failed Resources)
	// For MCP, we only care about the failed bindings/roles to send to the AI.
	// Result payload: resourcesresults.Result objects containing resourceID (encodes namespace/kind/name)
	// and per-control statuses. RawResource is empty in this map by design — the resourceID
	// is sufficient for the AI agent to identify the offending resource.
	var failedResources []interface{}
	totalFailed := 0
	for _, result := range scanData.ResourcesResult {
		if result.GetStatus(nil).IsFailed() {
			totalFailed++
			if len(failedResources) < maxFailedResources {
				failedResources = append(failedResources, result)
			}
		}
	}

	logger.L().Ctx(ctx).Info("Completed on-demand MCP RBAC security scan",
		helpers.Int("failed_resources", totalFailed),
		helpers.Int("returned_resources", len(failedResources)),
	)

	// Build response envelope so the AI agent knows if results were truncated.
	type scanResponse struct {
		TotalFailed     int           `json:"total_failed"`
		ReturnedFailed  int           `json:"returned_failed"`
		Truncated       bool          `json:"truncated"`
		FailedResources []interface{} `json:"failed_resources"`
	}
	response := scanResponse{
		TotalFailed:     totalFailed,
		ReturnedFailed:  len(failedResources),
		Truncated:       totalFailed > maxFailedResources,
		FailedResources: failedResources,
	}

	responseJSON, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal RBAC scan results: %w", err)
	}

	return responseJSON, nil
}
