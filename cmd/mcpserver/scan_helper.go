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
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/core/pkg/opaprocessor"
	"github.com/kubescape/kubescape/v4/core/pkg/policyhandler"
	"github.com/kubescape/kubescape/v4/core/pkg/resourcehandler"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/kubescape/opa-utils/resources"
)

const maxFailedResources = 100

type TargetResourceInfo struct {
	Kind               string `json:"kind,omitempty"`
	Name               string `json:"name,omitempty"`
	Namespace          string `json:"namespace,omitempty"`
	NamespaceDefaulted bool   `json:"namespace_defaulted,omitempty"`
}

type scanResponse struct {
	ComplianceScore      *float32            `json:"compliance_score,omitempty"`
	FrameworkName        string              `json:"framework_name,omitempty"`
	Degraded             bool                `json:"degraded"`
	NotEvaluatedControls int                 `json:"not_evaluated_controls"`
	TotalControls        int                 `json:"total_controls"`
	TotalFailed          int                 `json:"total_failed"`
	ReturnedFailed       int                 `json:"returned_failed"`
	Truncated            bool                `json:"truncated"`
	FailedResources      []interface{}       `json:"failed_resources"`
	Warning              string              `json:"warning,omitempty"`
	TargetResource       *TargetResourceInfo `json:"target_resource,omitempty"`
	ScanID               string              `json:"scan_id,omitempty"`
	NextOffset           *int                `json:"next_offset,omitempty"`
	ExpiresAt            *time.Time          `json:"expires_at,omitempty"`
	PaginationWarning    string              `json:"pagination_warning,omitempty"`
}

// scanRequest carries the parameters shared by every MCP scan entry point.
// It replaces a positional argument list that had grown to nine, where the
// three strings and the bool were easy to transpose silently at a call site.
type scanRequest struct {
	// namespace scopes a live-cluster scan. Empty or "*" means cluster-wide;
	// buildScanInfo normalizes "*" and derives the timeout from the scope.
	namespace          string
	namespaceDefaulted bool
	policyIdentifiers  []cautils.PolicyIdentifier
	// label names the scan in log lines and error messages ("RBAC", "Framework").
	label string
	// wantComplianceScore makes runScan report the framework compliance score
	// and buys the scan a longer timeout budget.
	wantComplianceScore bool
	// rsrcHandler overrides resource collection. Nil means build a
	// K8sResourceHandler against the live cluster; a FileResourceHandler here is
	// what makes the local-manifest scans work.
	rsrcHandler      resourcehandler.IResourceHandler
	inputPatterns    []string
	inMemoryManifest bool
	// customGetters replaces the policy getters wholesale. Nil means derive them
	// from the server's own policy getter.
	customGetters *cautils.Getters
	// scanObject, when non-nil, narrows the scan to one named workload. Both
	// resource handlers resolve it themselves — K8sResourceHandler through
	// cluster discovery, FileResourceHandler by matching the loaded manifests —
	// so it needs no plumbing beyond reaching ScanInfo. A nil value leaves every
	// other scan path unchanged.
	scanObject *objectsenvelopes.ScanObject
	// workspaceDir, when non-empty, confines local scans to files within this directory.
	workspaceDir string

	// Optional CLI filter fields
	includeKinds       string
	excludeKinds       string
	labelSelector      string
	excludeControls    []string
	minSeverity        string
	maxSeverity        string
	excludedNamespaces string
	limit              int
}

func runControlScan(ctx context.Context, ksServer *KubescapeMcpserver, namespace string, controlIDs []string, label string, filters ...scanFilterArgs) ([]byte, error) {
	policyIdentifiers := make([]cautils.PolicyIdentifier, len(controlIDs))
	for i, id := range controlIDs {
		policyIdentifiers[i] = cautils.PolicyIdentifier{Kind: apisv1.KindControl, Identifier: id}
	}
	req := scanRequest{
		namespace:         namespace,
		policyIdentifiers: policyIdentifiers,
		label:             label,
	}
	if len(filters) > 0 {
		filters[0].applyToRequest(&req)
	}
	return runScan(ctx, ksServer, req)
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

	policyGetter, err := ksServer.readyPolicyGetter(ctx)
	if err != nil {
		return nil, nil, err
	}
	getters := cautils.Getters{
		PolicyGetter: policyGetter,
	}
	if eg, ok := policyGetter.(getter.IExceptionsGetter); ok {
		getters.ExceptionsGetter = eg
	}
	if cig, ok := policyGetter.(getter.IControlsInputsGetter); ok {
		getters.ControlsInputsGetter = cig
	}
	if atg, ok := policyGetter.(getter.IAttackTracksGetter); ok {
		getters.AttackTracksGetter = atg
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

	if req.minSeverity != "" || req.maxSeverity != "" {
		resultshandling.ApplySeverityFilters(scanData, req.minSeverity, req.maxSeverity)
	}

	var complianceScore *float32
	var frameworkName string
	degraded := false
	notEvaluated := 0
	totalControls := 0
	var summary *reportsummary.SummaryDetails

	if scanData.Report != nil {
		summary = &scanData.Report.SummaryDetails
		degraded = scanData.ScanCoverage.Degraded || processErr != nil
		notEvaluated = len(scanData.ScanCoverage.NotEvaluatedControls)
		if (req.minSeverity != "" || req.maxSeverity != "") && notEvaluated > 0 {
			count := 0
			for _, ne := range scanData.ScanCoverage.NotEvaluatedControls {
				if _, ok := scanData.Report.SummaryDetails.Controls[ne.ControlID]; ok {
					count++
				}
			}
			notEvaluated = count
		}
		totalControls = len(scanData.Report.SummaryDetails.Controls)

		if req.wantComplianceScore && len(scanData.Report.SummaryDetails.Frameworks) > 0 {
			score := scanData.Report.SummaryDetails.Frameworks[0].ComplianceScore
			complianceScore = &score
			frameworkName = scanData.Report.SummaryDetails.Frameworks[0].Name
		} else if req.wantComplianceScore {
			logger.L().Ctx(ctx).Warning("framework scan produced no framework summary")
		}
	}

	limit := maxFailedResources
	prepared, _ := ctx.Value(preparedScanResultsKey{}).(*preparedScanResults)
	// Shared execution must cover the largest supported page. Each caller
	// applies its own limit after the shared result is available.
	if prepared == nil && req.limit > 0 {
		limit = req.limit
	}
	response, ordered := buildRankedScanResponse(summary, scanData.ResourcesResult, complianceScore, frameworkName, degraded, notEvaluated, totalControls, limit)
	if req.namespaceDefaulted && req.scanObject != nil {
		response.Warning = "Workload namespace was omitted and defaulted to 'default'. If your workload is in another namespace, specify 'namespace' explicitly or pass '*' to search cluster-wide."
		response.TargetResource = &TargetResourceInfo{
			Kind:               req.scanObject.GetKind(),
			Name:               req.scanObject.GetName(),
			Namespace:          req.scanObject.GetNamespace(),
			NamespaceDefaulted: true,
		}
	}

	logger.L().Ctx(ctx).Info(fmt.Sprintf("Completed on-demand MCP %s security scan", req.label),
		helpers.Int("failed_resources", response.TotalFailed),
		helpers.Int("returned_resources", response.ReturnedFailed),
	)

	if prepared != nil {
		if response.Truncated {
			if err := prepared.buildSnapshot(response, len(ordered), func(i int) any {
				return scanData.ResourcesResult[ordered[i].key]
			}); err != nil {
				return nil, err
			}
		}
		if prepared.oversized {
			response.PaginationWarning = "Full results could not be retained (retention limit exceeded); narrow the scan scope."
		}
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal %s scan results: %w", req.label, err)
	}

	return responseJSON, nil
}

// workloadScanTimeout is the budget for a single-workload scan.
//
// The namespace-derived budgets below assume the scan's cost tracks how many
// resources it collects, which is what a namespace narrows. A single-workload
// scan inverts that: it collects one resource, and its cost is dominated by
// loading the workload control set — work that is the same size whether or not
// a namespace was given. Measured end to end against one Deployment on a warm
// policy cache, that load and evaluation takes ~15s, so the 10s a namespaced
// scan would otherwise get is not survivable, and picking a budget from the
// namespace is meaningless here. This matches what a cluster-wide framework
// scan already gets for comparable policy work.
const workloadScanTimeout = 120 * time.Second

func buildScanInfo(req scanRequest) *cautils.ScanInfo {
	namespace := req.namespace
	timeout := 10 * time.Second
	switch {
	case req.scanObject != nil:
		timeout = workloadScanTimeout
	case req.wantComplianceScore:
		timeout = 30 * time.Second
	}
	if req.scanObject == nil && (namespace == "" || namespace == "*") {
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
		ScanAll:            false,
		IncludeNamespaces:  namespace,
		ExcludedNamespaces: req.excludedNamespaces,
		ScanTimeout:        timeout,
		InputPatterns:      req.inputPatterns,
		InMemoryManifest:   req.inMemoryManifest,
		ScanObject:         req.scanObject,
		WorkspaceDir:       req.workspaceDir,
		IncludeKinds:       req.includeKinds,
		ExcludeKinds:       req.excludeKinds,
		LabelSelector:      req.labelSelector,
		ExcludeControls:    req.excludeControls,
	}
}

func resourceMaxSeverityRank(summary *reportsummary.SummaryDetails, result *resourcesresults.Result) int {
	if summary == nil || len(summary.Controls) == 0 {
		return 0
	}
	maxRank := 0
	for _, ac := range result.AssociatedControls {
		if !cautils.ControlStatus(summary, &ac).IsFailed() {
			continue
		}
		if ctrl, ok := summary.Controls[ac.GetID()]; ok {
			rank := apis.ControlSeverityToInt(ctrl.GetScoreFactor())
			if rank > maxRank {
				maxRank = rank
			}
		}
	}
	return maxRank
}

func buildScanResponse(summary *reportsummary.SummaryDetails, results map[string]resourcesresults.Result, complianceScore *float32, frameworkName string, degraded bool, notEvaluated int, totalControls int) scanResponse {
	return buildScanResponseWithLimit(summary, results, complianceScore, frameworkName, degraded, notEvaluated, totalControls, maxFailedResources)
}

func buildScanResponseWithLimit(summary *reportsummary.SummaryDetails, results map[string]resourcesresults.Result, complianceScore *float32, frameworkName string, degraded bool, notEvaluated int, totalControls, limit int) scanResponse {
	response, _ := buildRankedScanResponse(summary, results, complianceScore, frameworkName, degraded, notEvaluated, totalControls, limit)
	return response
}

type rankedScanResource struct {
	key  string
	rank int
}

func buildRankedScanResponse(summary *reportsummary.SummaryDetails, results map[string]resourcesresults.Result, complianceScore *float32, frameworkName string, degraded bool, notEvaluated int, totalControls, limit int) (scanResponse, []rankedScanResource) {
	failed := make([]rankedScanResource, 0, len(results))
	for k, result := range results {
		if cautils.ResourceStatus(summary, &result).IsFailed() {
			failed = append(failed, rankedScanResource{
				key:  k,
				rank: resourceMaxSeverityRank(summary, &result),
			})
		}
	}

	sort.SliceStable(failed, func(i, j int) bool {
		if failed[i].rank != failed[j].rank {
			return failed[i].rank > failed[j].rank
		}
		return failed[i].key < failed[j].key
	})

	totalFailed := len(failed)
	returnedCount := totalFailed
	if limit < returnedCount {
		returnedCount = limit
	}

	failedResources := make([]interface{}, 0, returnedCount)
	for i := 0; i < returnedCount; i++ {
		failedResources = append(failedResources, results[failed[i].key])
	}

	return scanResponse{
		ComplianceScore:      complianceScore,
		FrameworkName:        frameworkName,
		Degraded:             degraded,
		NotEvaluatedControls: notEvaluated,
		TotalControls:        totalControls,
		TotalFailed:          totalFailed,
		ReturnedFailed:       len(failedResources),
		Truncated:            totalFailed > limit,
		FailedResources:      failedResources,
	}, failed
}
