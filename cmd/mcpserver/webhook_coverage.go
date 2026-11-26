package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/kubescape/kubescape/v4/core/pkg/webhookcoverage"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/mark3labs/mcp-go/mcp"
)

const (
	webhookCoverageToolName = "analyze_admission_webhook_coverage"

	defaultWebhookWorkloadLimit = 100
	maxWebhookWorkloadLimit     = 1000

	// webhookCoverageControl is the control a live scan is scoped to. The tool
	// does not widen the scan to make the analysis complete: it reports what
	// that scan collected, and says when that is not everything.
	webhookCoverageControl = "C-0017"
)

// errWebhookAnalysisUnavailable reports a scan that finished without producing
// a webhook coverage analysis, for example because the cluster connection did
// not allow webhook configurations to be collected at all.
var errWebhookAnalysisUnavailable = errors.New("the scan did not produce an admission webhook coverage analysis")

// webhookCoverageScanFn is a package-level var so tests can supply a scan
// result without a cluster, as rbacScanFn does.
var webhookCoverageScanFn = func(ctx context.Context, s *KubescapeMcpserver, limit int) ([]byte, error) {
	return s.RunWebhookCoverageScan(ctx, limit)
}

// webhookCoverageLimitations is returned with every response. It states what a
// verdict does and does not establish.
var webhookCoverageLimitations = []string{
	"Each result answers one question: would a synthetic CREATE admission request for this workload satisfy this webhook's matching criteria (rules, namespaceSelector, objectSelector, matchPolicy). Only CREATE is analyzed, for Pod, ReplicationController, Deployment, StatefulSet, DaemonSet, ReplicaSet, Job and CronJob.",
	"Matched does not prove the webhook is called, is healthy or available, or enforces any policy.",
	"NotMatched does not prove the workload is unprotected or that a bypass exists: other webhooks, admission policies and built-in admission plugins are not evaluated.",
	"Indeterminate means the available information could not decide the match; see reasons. It is neither Matched nor NotMatched.",
	"Read status and complete before relying on an empty or clean-looking result: an incomplete analysis does not describe the whole cluster.",
}

type webhookSourceJSON struct {
	Available      bool     `json:"available"`
	Complete       bool     `json:"complete"`
	Configurations int      `json:"configurations"`
	Error          string   `json:"error,omitempty"`
	ErrorKind      string   `json:"error_kind,omitempty"`
	DecodeErrors   []string `json:"decode_errors,omitempty"`
}

type webhookResultJSON struct {
	Type          string   `json:"type"`
	Configuration string   `json:"configuration"`
	Webhook       string   `json:"webhook"`
	Verdict       string   `json:"verdict"`
	Reasons       []string `json:"reasons"`
}

type webhookWorkloadJSON struct {
	APIVersion           string              `json:"api_version"`
	Kind                 string              `json:"kind"`
	Namespace            string              `json:"namespace,omitempty"`
	Name                 string              `json:"name"`
	NamespaceLabelsKnown bool                `json:"namespace_labels_known"`
	Results              []webhookResultJSON `json:"results"`
}

type webhookSummaryJSON struct {
	Type          string `json:"type"`
	Configuration string `json:"configuration"`
	Webhook       string `json:"webhook"`
	Matched       int    `json:"matched"`
	NotMatched    int    `json:"not_matched"`
	Indeterminate int    `json:"indeterminate"`
}

type webhookSkippedJSON struct {
	APIVersion string `json:"api_version"`
	Kind       string `json:"kind"`
	Reason     string `json:"reason"`
	Count      int    `json:"count"`
}

type webhookCoverageResponse struct {
	// Status is "complete" or "incomplete". An unavailable analysis is
	// reported as an error, never as a response with this shape.
	Status              string                `json:"status"`
	Complete            bool                  `json:"complete"`
	Operation           string                `json:"operation"`
	ValidatingSource    webhookSourceJSON     `json:"validating_source"`
	MutatingSource      webhookSourceJSON     `json:"mutating_source"`
	WorkloadsComplete   bool                  `json:"workloads_complete"`
	ConfigurationIssues []string              `json:"configuration_issues"`
	Webhooks            []webhookSummaryJSON  `json:"webhooks"`
	TotalWorkloads      int                   `json:"total_workloads"`
	ReturnedWorkloads   int                   `json:"returned_workloads"`
	Truncated           bool                  `json:"truncated"`
	Workloads           []webhookWorkloadJSON `json:"workloads"`
	Skipped             []webhookSkippedJSON  `json:"skipped"`
	Limitations         []string              `json:"limitations"`
}

func webhookSourceResponse(s webhookcoverage.Source, configurations int) webhookSourceJSON {
	out := webhookSourceJSON{Available: s.Available, Complete: s.Complete(), Configurations: configurations}
	if s.Err != nil {
		out.Error = s.Err.Error()
		switch {
		case errors.Is(s.Err, webhookcoverage.ErrUnsupported):
			out.ErrorKind = "unsupported"
		case errors.Is(s.Err, webhookcoverage.ErrForbidden):
			out.ErrorKind = "forbidden"
		default:
			out.ErrorKind = "other"
		}
	}
	for _, e := range s.DecodeErrs {
		out.DecodeErrors = append(out.DecodeErrors, e.Error())
	}
	return out
}

// buildWebhookCoverageResponse converts the analysis the scan produced into
// the tool's JSON. It maps fields one to one: no verdict, reason, count or
// completeness flag is computed here. Only the per-workload detail is capped
// at limit, and the per-webhook summaries always cover every workload.
func buildWebhookCoverageResponse(a *webhookcoverage.Analysis, limit int) ([]byte, error) {
	if a == nil {
		return nil, errWebhookAnalysisUnavailable
	}
	status := "incomplete"
	if a.Complete() {
		status = "complete"
	}
	resp := webhookCoverageResponse{
		Status:              status,
		Complete:            a.Complete(),
		Operation:           string(a.Operation),
		ValidatingSource:    webhookSourceResponse(a.ValidatingSource, a.ValidatingConfigurations),
		MutatingSource:      webhookSourceResponse(a.MutatingSource, a.MutatingConfigurations),
		WorkloadsComplete:   a.SubjectsComplete,
		ConfigurationIssues: append([]string{}, a.ConfigurationIssues...),
		Webhooks:            make([]webhookSummaryJSON, 0, len(a.Webhooks)),
		TotalWorkloads:      len(a.Workloads),
		Workloads:           []webhookWorkloadJSON{},
		Skipped:             make([]webhookSkippedJSON, 0, len(a.Skipped)),
		Limitations:         webhookCoverageLimitations,
	}
	for _, w := range a.Webhooks {
		resp.Webhooks = append(resp.Webhooks, webhookSummaryJSON{
			Type: string(w.Type), Configuration: w.Configuration, Webhook: w.Webhook,
			Matched: w.Matched, NotMatched: w.NotMatched, Indeterminate: w.Indeterminate,
		})
	}
	for _, s := range a.Skipped {
		resp.Skipped = append(resp.Skipped, webhookSkippedJSON{APIVersion: s.APIVersion, Kind: s.Kind, Reason: s.Reason, Count: s.Count})
	}
	for i, w := range a.Workloads {
		if i >= limit {
			resp.Truncated = true
			break
		}
		entry := webhookWorkloadJSON{
			APIVersion: w.APIVersion, Kind: w.Kind, Namespace: w.Namespace, Name: w.Name,
			NamespaceLabelsKnown: w.NamespaceLabelsKnown,
			Results:              make([]webhookResultJSON, 0, len(w.Results)),
		}
		for _, r := range w.Results {
			reasons := make([]string, 0, len(r.Reasons))
			for _, reason := range r.Reasons {
				reasons = append(reasons, string(reason))
			}
			entry.Results = append(entry.Results, webhookResultJSON{
				Type: string(r.Type), Configuration: r.Configuration, Webhook: r.Webhook,
				Verdict: string(r.Verdict), Reasons: reasons,
			})
		}
		resp.Workloads = append(resp.Workloads, entry)
	}
	resp.ReturnedWorkloads = len(resp.Workloads)
	return json.MarshalIndent(resp, "", "  ")
}

// webhookCoverageScanRequest is the scan the tool runs: cluster-wide, with no
// filters, scoped to one control. It is a function so a test can check that
// the scan is never narrowed or widened by anything the caller passes.
func webhookCoverageScanRequest() scanRequest {
	return scanRequest{
		policyIdentifiers: []cautils.PolicyIdentifier{{Kind: apisv1.KindControl, Identifier: webhookCoverageControl}},
		label:             "Webhook coverage",
	}
}

// webhookCoverageFromScan turns a finished scan into the tool's response. The
// analysis is built by the same function a CLI scan uses, so the workload
// selection and the completeness decision are not repeated here.
func webhookCoverageFromScan(ctx context.Context, scanData *cautils.OPASessionObj, req scanRequest, limit int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if scanData == nil {
		return nil, errWebhookAnalysisUnavailable
	}
	return buildWebhookCoverageResponse(resultshandling.BuildWebhookCoverage(scanData, buildScanInfo(req)), limit)
}

// RunWebhookCoverageScan runs the standard on-demand live scan, scoped to one
// control, and returns the admission webhook coverage analysis that scan
// collected.
func (ksServer *KubescapeMcpserver) RunWebhookCoverageScan(ctx context.Context, limit int) ([]byte, error) {
	req := webhookCoverageScanRequest()
	scanData, _, err := executeScan(ctx, ksServer, req)
	if err != nil {
		return nil, err
	}
	return webhookCoverageFromScan(ctx, scanData, req, limit)
}

func createWebhookCoverageTools(ksServer *KubescapeMcpserver) {
	tool := mcp.NewTool(
		webhookCoverageToolName,
		mcp.WithDescription("Report, from a live cluster scan, which validating and mutating admission webhooks would match a synthetic CREATE request for each collected workload (Pod, ReplicationController, Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob). Each result is Matched, NotMatched or Indeterminate, with reasons. Matched does not prove a webhook is healthy or enforces anything; NotMatched does not prove a workload is unprotected; Indeterminate is neither. Check 'complete', the two sources and 'workloads_complete' before treating an empty or clean-looking result as covering the cluster: the scan is scoped to one control, so workloads of some kinds may not have been collected. Only CREATE is analyzed. Requires list permission on validatingwebhookconfigurations and mutatingwebhookconfigurations."),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithNumber("limit",
			mcp.Description(fmt.Sprintf("Maximum number of workloads whose per-webhook results are returned, 1–%d (optional, default %d). 'webhooks' always summarizes every analyzed workload; 'truncated' says whether workload detail was cut.", maxWebhookWorkloadLimit, defaultWebhookWorkloadLimit)),
		),
	)
	ksServer.s.AddTool(tool, ksServer.toolHandler(tool.Name))
}

func (ksServer *KubescapeMcpserver) callWebhookCoverage(ctx context.Context, arguments map[string]any) (*mcp.CallToolResult, error) {
	limit := defaultWebhookWorkloadLimit
	if requested, set, argErr := mcpIntArg(arguments, "limit"); argErr != nil {
		return argErr, nil
	} else if set {
		if requested < 1 || requested > maxWebhookWorkloadLimit {
			return mcpToolError(ErrCodeInvalidArgument,
				fmt.Sprintf("limit must be between 1 and %d", maxWebhookWorkloadLimit),
				map[string]any{"argument": "limit"}), nil
		}
		limit = requested
	}
	for name := range arguments {
		if name != "limit" {
			return mcpToolError(ErrCodeInvalidArgument, fmt.Sprintf("unknown argument %q", name), map[string]any{"argument": name}), nil
		}
	}

	key := "webhook_coverage:" + strconv.Itoa(limit)
	v, err := ksServer.doScanChan(ctx, key, func(scanCtx context.Context) (interface{}, error) {
		return webhookCoverageScanFn(scanCtx, ksServer, limit)
	})
	if err != nil {
		if errors.Is(err, errWebhookAnalysisUnavailable) {
			return mcpToolError(ErrCodeAnalysisUnavailable,
				"the scan completed but produced no admission webhook analysis; webhook configurations could not be collected, which is not the same as the cluster having none", nil), nil
		}
		code := classifyScanError(err)
		return mcpToolError(code, classifyScanErrorMessage(code, "webhook coverage", err), nil), nil
	}
	return mcp.NewToolResultText(string(v.([]byte))), nil
}
