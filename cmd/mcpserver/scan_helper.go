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
	ComplianceScore      *float32      `json:"compliance_score,omitempty"`
	FrameworkName        string        `json:"framework_name,omitempty"`
	Degraded             bool          `json:"degraded"`
	NotEvaluatedControls int           `json:"not_evaluated_controls"`
	TotalControls        int           `json:"total_controls"`
	TotalFailed          int           `json:"total_failed"`
	ReturnedFailed       int           `json:"returned_failed"`
	Truncated            bool          `json:"truncated"`
	FailedResources      []interface{} `json:"failed_resources"`
}

func runControlScan(ctx context.Context, ksServer *KubescapeMcpserver, namespace string, controlIDs []string, label string) ([]byte, error) {
	policyIdentifiers := make([]cautils.PolicyIdentifier, len(controlIDs))
	for i, id := range controlIDs {
		policyIdentifiers[i] = cautils.PolicyIdentifier{Kind: apisv1.KindControl, Identifier: id}
	}
	return runScan(ctx, ksServer, namespace, policyIdentifiers, label, false, nil, nil)
}

func runScan(ctx context.Context, ksServer *KubescapeMcpserver, namespace string, policyIdentifiers []cautils.PolicyIdentifier, label string, wantComplianceScore bool, rsrcHandler resourcehandler.IResourceHandler, inputPatterns []string) ([]byte, error) {
	logger.L().Ctx(ctx).Info(fmt.Sprintf("Initiating on-demand MCP %s security scan", label), helpers.String("namespace", namespace))

	var client *k8sinterface.KubernetesApi
	if rsrcHandler == nil {
		if !k8sinterface.IsConnectedToCluster() {
			return nil, fmt.Errorf("no reachable kubernetes cluster: ensure KUBECONFIG is set or the server is running inside a cluster")
		}
		client = ksServer.getK8sClient()
	}

	timeout := 10 * time.Second
	if wantComplianceScore {
		timeout = 30 * time.Second
	}
	if namespace == "" || namespace == "*" {
		if wantComplianceScore {
			timeout = 120 * time.Second
		} else {
			timeout = 60 * time.Second
		}
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
		InputPatterns:     inputPatterns,
	}

	scanCtx, cancel := context.WithTimeout(ctx, scanInfo.ScanTimeout)
	defer cancel()

	policyHandler := policyhandler.NewRequestScopedPolicyHandler("")
	defer policyHandler.Close()
	scanData, err := policyHandler.CollectPolicies(scanCtx, scanInfo.PolicyIdentifier, scanInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to collect %s policies: %w", label, err)
	}

	if rsrcHandler == nil {
		rsrcHandler = resourcehandler.NewK8sResourceHandler(scanCtx, client, nil, nil, "")
	}
	if err := resourcehandler.CollectResources(scanCtx, rsrcHandler, scanData, scanInfo); err != nil {
		return nil, fmt.Errorf("failed to collect %s resources: %w", label, err)
	}

	k8sConfig := k8sinterface.GetK8sConfig()
	if client != nil {
		k8sConfig = client.K8SConfig
	}
	deps := resources.NewRegoDependenciesData(k8sConfig, "")
	opap := opaprocessor.NewOPAProcessor(scanData, deps, "", scanInfo.ExcludedNamespaces, scanInfo.IncludeNamespaces, false, nil)
	if wantComplianceScore {
		opap.ControlTimeout = timeout / 4
	}

	err = opap.ProcessRulesListener(scanCtx, cautils.NewProgressHandler(""))
	if err != nil {
		logger.L().Ctx(ctx).Warning(fmt.Sprintf("failed to fully process %s rules (partial results will be returned)", label), helpers.Error(err))
	}

	var complianceScore *float32
	var frameworkName string
	degraded := false
	notEvaluated := 0
	totalControls := 0

	if scanData.Report != nil {
		degraded = scanData.ScanCoverage.Degraded || err != nil
		notEvaluated = len(scanData.ScanCoverage.NotEvaluatedControls)
		totalControls = len(scanData.Report.SummaryDetails.Controls)

		if wantComplianceScore && len(scanData.Report.SummaryDetails.Frameworks) > 0 {
			score := scanData.Report.SummaryDetails.Frameworks[0].ComplianceScore
			complianceScore = &score
			frameworkName = scanData.Report.SummaryDetails.Frameworks[0].Name
		} else if wantComplianceScore {
			logger.L().Ctx(ctx).Warning("framework scan produced no framework summary")
		}
	}

	response := buildScanResponse(scanData.ResourcesResult, complianceScore, frameworkName, degraded, notEvaluated, totalControls)

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

func buildScanResponse(results map[string]resourcesresults.Result, complianceScore *float32, frameworkName string, degraded bool, notEvaluated int, totalControls int) scanResponse {
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
		ComplianceScore:      complianceScore,
		FrameworkName:        frameworkName,
		Degraded:             degraded,
		NotEvaluatedControls: notEvaluated,
		TotalControls:        totalControls,
		TotalFailed:          totalFailed,
		ReturnedFailed:       len(failedResources),
		Truncated:            totalFailed > maxFailedResources,
		FailedResources:      failedResources,
	}
}
