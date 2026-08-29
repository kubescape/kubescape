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
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/opaprocessor"
	"github.com/kubescape/kubescape/v4/core/pkg/policyhandler"
	"github.com/kubescape/kubescape/v4/core/pkg/resourcehandler"
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

// scanRequest carries the parameters shared by every MCP scan entry point.
// It replaces a positional argument list that had grown to nine, where the
// three strings and the bool were easy to transpose silently at a call site.
type scanRequest struct {
	// namespace scopes a live-cluster scan. Empty or "*" means cluster-wide;
	// buildScanInfo normalizes "*" and derives the timeout from the scope.
	namespace         string
	policyIdentifiers []cautils.PolicyIdentifier
	// label names the scan in log lines and error messages ("RBAC", "Framework").
	label string
	// wantComplianceScore makes runScan report the framework compliance score
	// and buys the scan a longer timeout budget.
	wantComplianceScore bool
	// rsrcHandler overrides resource collection. Nil means build a
	// K8sResourceHandler against the live cluster; a FileResourceHandler here is
	// what makes the local-manifest scans work.
	rsrcHandler   resourcehandler.IResourceHandler
	inputPatterns []string
	// customGetters replaces the policy getters wholesale. Nil means derive them
	// from the server's own policy getter.
	customGetters *cautils.Getters
}

func runControlScan(ctx context.Context, ksServer *KubescapeMcpserver, namespace string, controlIDs []string, label string) ([]byte, error) {
	policyIdentifiers := make([]cautils.PolicyIdentifier, len(controlIDs))
	for i, id := range controlIDs {
		policyIdentifiers[i] = cautils.PolicyIdentifier{Kind: apisv1.KindControl, Identifier: id}
	}
	return runScan(ctx, ksServer, scanRequest{
		namespace:         namespace,
		policyIdentifiers: policyIdentifiers,
		label:             label,
	})
}

// executeScan runs the collect-policies → collect-resources → OPA pipeline and
// returns the raw session object. It is the shared core of runScan (which
// summarizes the session for scan tools) and runIaCScanControlsReport (which
// serializes it as a full PostureReport for the remediation tool).
//
// The second return value is the non-fatal rule-processing error: rules that
// failed to evaluate still leave usable partial results, so callers fold it
// into a "degraded" signal rather than treating it as a failure. The third is a
// genuine failure, where scanData is nil.
func executeScan(ctx context.Context, ksServer *KubescapeMcpserver, req scanRequest) (*cautils.OPASessionObj, error, error) {
	logger.L().Ctx(ctx).Info(fmt.Sprintf("Initiating on-demand MCP %s security scan", req.label), helpers.String("namespace", req.namespace))

	rsrcHandler := req.rsrcHandler

	var client *k8sinterface.KubernetesApi
	if rsrcHandler == nil {
		var err error
		client, err = ksServer.getK8sClient()
		if err != nil {
			return nil, nil, err
		}
	}

	scanInfo := buildScanInfo(req)

	policyGetter := ksServer.getPolicyGetter()
	getters := cautils.Getters{
		PolicyGetter:         policyGetter,
		ExceptionsGetter:     policyGetter,
		ControlsInputsGetter: policyGetter,
		AttackTracksGetter:   policyGetter,
	}
	if req.customGetters != nil {
		getters = *req.customGetters
	}

	scanCtx, cancel := context.WithTimeout(ctx, scanInfo.ScanTimeout)
	defer cancel()

	policyHandler := policyhandler.NewRequestScopedPolicyHandler("")
	defer policyHandler.Close()
	scanData, err := policyHandler.CollectPolicies(scanCtx, req.policyIdentifiers, scanInfo, &getters)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to collect %s policies: %w", req.label, err)
	}

	if rsrcHandler == nil {
		rsrcHandler = resourcehandler.NewK8sResourceHandler(scanCtx, client, nil, nil, "")
	}
	if err := resourcehandler.CollectResources(scanCtx, rsrcHandler, scanData, scanInfo); err != nil {
		return nil, nil, fmt.Errorf("failed to collect %s resources: %w", req.label, err)
	}

	k8sConfig := k8sinterface.GetK8sConfig()
	if client != nil {
		k8sConfig = client.K8SConfig
	}
	deps := resources.NewRegoDependenciesData(k8sConfig, "")
	opap := opaprocessor.NewOPAProcessor(scanData, deps, "", scanInfo.ExcludedNamespaces, scanInfo.IncludeNamespaces, false, nil)
	if req.wantComplianceScore {
		opap.ControlTimeout = scanInfo.ScanTimeout / 4
	}

	processErr := opap.ProcessRulesListener(scanCtx, cautils.NewProgressHandler(""))
	if processErr != nil {
		logger.L().Ctx(ctx).Warning(fmt.Sprintf("failed to fully process %s rules (partial results will be returned)", req.label), helpers.Error(processErr))
	}

	return scanData, processErr, nil
}

func runScan(ctx context.Context, ksServer *KubescapeMcpserver, req scanRequest) ([]byte, error) {
	scanData, processErr, err := executeScan(ctx, ksServer, req)
	if err != nil {
		return nil, err
	}

	var complianceScore *float32
	var frameworkName string
	degraded := false
	notEvaluated := 0
	totalControls := 0

	if scanData.Report != nil {
		degraded = scanData.ScanCoverage.Degraded || processErr != nil
		notEvaluated = len(scanData.ScanCoverage.NotEvaluatedControls)
		totalControls = len(scanData.Report.SummaryDetails.Controls)

		if req.wantComplianceScore && len(scanData.Report.SummaryDetails.Frameworks) > 0 {
			score := scanData.Report.SummaryDetails.Frameworks[0].ComplianceScore
			complianceScore = &score
			frameworkName = scanData.Report.SummaryDetails.Frameworks[0].Name
		} else if req.wantComplianceScore {
			logger.L().Ctx(ctx).Warning("framework scan produced no framework summary")
		}
	}

	response := buildScanResponse(scanData.ResourcesResult, complianceScore, frameworkName, degraded, notEvaluated, totalControls)

	logger.L().Ctx(ctx).Info(fmt.Sprintf("Completed on-demand MCP %s security scan", req.label),
		helpers.Int("failed_resources", response.TotalFailed),
		helpers.Int("returned_resources", response.ReturnedFailed),
	)

	responseJSON, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal %s scan results: %w", req.label, err)
	}

	return responseJSON, nil
}

func buildScanInfo(req scanRequest) *cautils.ScanInfo {
	namespace := req.namespace
	timeout := 10 * time.Second
	if req.wantComplianceScore {
		timeout = 30 * time.Second
	}
	if namespace == "" || namespace == "*" {
		if req.wantComplianceScore {
			timeout = 120 * time.Second
		} else {
			timeout = 60 * time.Second
		}
	}
	if namespace == "*" {
		namespace = ""
	}
	return &cautils.ScanInfo{
		ScanAll:           false,
		IncludeNamespaces: namespace,
		ScanTimeout:       timeout,
		InputPatterns:     req.inputPatterns,
	}
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
