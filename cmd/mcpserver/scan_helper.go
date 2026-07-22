package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/opaprocessor"
	"github.com/kubescape/kubescape/v3/core/pkg/policyhandler"
	"github.com/kubescape/kubescape/v3/core/pkg/resourcehandler"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/kubescape/opa-utils/resources"
)

const maxFailedResources = 100

type scanResponse struct {
	ComplianceScore float32       `json:"compliance_score,omitempty"`
	TotalFailed     int           `json:"total_failed"`
	ReturnedFailed  int           `json:"returned_failed"`
	Truncated       bool          `json:"truncated"`
	FailedResources []interface{} `json:"failed_resources"`
}

func runControlScan(ctx context.Context, ksServer *KubescapeMcpserver, namespace string, controlIDs []string, label string) ([]byte, error) {
	policyIdentifiers := make([]cautils.PolicyIdentifier, len(controlIDs))
	for i, id := range controlIDs {
		policyIdentifiers[i] = cautils.PolicyIdentifier{Kind: apisv1.KindControl, Identifier: id}
	}
	return runScan(ctx, ksServer, namespace, policyIdentifiers, label)
}

func runFrameworkScan(ctx context.Context, ksServer *KubescapeMcpserver, namespace string, frameworkIDs []string, label string) ([]byte, error) {
	policyIdentifiers := make([]cautils.PolicyIdentifier, len(frameworkIDs))
	for i, id := range frameworkIDs {
		policyIdentifiers[i] = cautils.PolicyIdentifier{Kind: apisv1.KindFramework, Identifier: id}
	}
	return runScan(ctx, ksServer, namespace, policyIdentifiers, label)
}

func runScan(ctx context.Context, ksServer *KubescapeMcpserver, namespace string, policyIdentifiers []cautils.PolicyIdentifier, label string) ([]byte, error) {
	logger.L().Ctx(ctx).Info(fmt.Sprintf("Initiating on-demand MCP %s security scan", label), helpers.String("namespace", namespace))

	if !k8sinterface.IsConnectedToCluster() {
		return nil, fmt.Errorf("no reachable kubernetes cluster: ensure KUBECONFIG is set or the server is running inside a cluster")
	}

	client := ksServer.getK8sClient()

	timeout := 10 * time.Second
	if namespace == "" || namespace == "*" {
		timeout = 60 * time.Second
	}

	scanInfo := &cautils.ScanInfo{
		Getters: cautils.Getters{
			PolicyGetter:         ksServer.policyGetter,
			ExceptionsGetter:     ksServer.policyGetter,
			ControlsInputsGetter: ksServer.policyGetter,
			AttackTracksGetter:   ksServer.policyGetter,
		},
		ScanAll:           false,
		PolicyIdentifier:  policyIdentifiers,
		IncludeNamespaces: namespace,
		ScanTimeout:       timeout,
	}

	scanCtx, cancel := context.WithTimeout(ctx, scanInfo.ScanTimeout)
	defer cancel()

	policyHandler := policyhandler.NewRequestScopedPolicyHandler("")
	defer policyHandler.Close()
	scanData, err := policyHandler.CollectPolicies(scanCtx, scanInfo.PolicyIdentifier, scanInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to collect %s policies: %w", label, err)
	}

	k8sHandler := resourcehandler.NewK8sResourceHandler(scanCtx, client, nil, nil, "")
	if err := resourcehandler.CollectResources(scanCtx, k8sHandler, scanData, scanInfo); err != nil {
		return nil, fmt.Errorf("failed to collect %s resources: %w", label, err)
	}

	deps := resources.NewRegoDependenciesData(client.K8SConfig, "")
	opap := opaprocessor.NewOPAProcessor(scanData, deps, "", scanInfo.ExcludedNamespaces, scanInfo.IncludeNamespaces, false, nil)

	if err := opap.ProcessRulesListener(scanCtx, cautils.NewProgressHandler("")); err != nil {
		return nil, fmt.Errorf("failed to process %s rules: %w", label, err)
	}

	complianceScore := float32(0.0)
	if scanData.Report != nil {
		complianceScore = scanData.Report.SummaryDetails.ComplianceScore
	}

	response := buildScanResponse(scanData.ResourcesResult, complianceScore)

	logger.L().Ctx(ctx).Info(fmt.Sprintf("Completed on-demand MCP %s security scan", label),
		helpers.Int("failed_resources", response.TotalFailed),
		helpers.Int("returned_resources", response.ReturnedFailed),
	)

	responseJSON, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal %s scan results: %w", label, err)
	}

	return responseJSON, nil
}

func buildScanResponse(results map[string]resourcesresults.Result, complianceScore float32) scanResponse {
	failedResources := make([]interface{}, 0)
	totalFailed := 0

	keys := make([]string, 0, len(results))
	for k := range results {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		result := results[k]
		if result.GetStatus(nil).IsFailed() {
			totalFailed++
			if len(failedResources) < maxFailedResources {
				failedResources = append(failedResources, result)
			}
		}
	}

	return scanResponse{
		ComplianceScore: complianceScore,
		TotalFailed:     totalFailed,
		ReturnedFailed:  len(failedResources),
		Truncated:       totalFailed > maxFailedResources,
		FailedResources: failedResources,
	}
}
