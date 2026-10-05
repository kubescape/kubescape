package mcpserver

import (
	"context"
	"errors"
	"fmt"

	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/diff"
	"github.com/mark3labs/mcp-go/mcp"
)

// diffReportsResult is the structured payload returned by diff_reports. Only
// one of Posture or Vulnerability is set, matching Kind, so each report kind
// keeps its own existing shape instead of being forced into a shared schema.
type diffReportsResult struct {
	Kind          string                       `json:"kind"`
	BaseReport    string                       `json:"base_report"`
	HeadReport    string                       `json:"head_report"`
	Posture       *diff.ChangeSet              `json:"posture,omitempty"`
	Vulnerability *diff.VulnerabilityChangeSet `json:"vulnerability,omitempty"`
}

// reportKindLabel renders a diff.ReportKind as the lowercase string used in
// tool output and error details.
func reportKindLabel(kind diff.ReportKind) string {
	switch kind {
	case diff.PostureReport:
		return "posture"
	case diff.VulnerabilityReport:
		return "vulnerability"
	default:
		return "unreadable"
	}
}

// createDiffReportsTools registers diff_reports, which compares two
// already-produced Kubescape scan reports the same way "kubescape diff"
// does: it reuses diff.CompareReports to detect each report's kind and
// dispatch to the matching comparison routine, rather than hardcoding the
// posture path or reimplementing the CLI's dispatch logic.
func createDiffReportsTools(ksServer *KubescapeMcpserver) {
	tool := mcp.NewTool(
		"diff_reports",
		mcp.WithDescription("Compare two already-produced Kubescape scan report files (JSON) and return what changed, reusing the same comparison engine as \"kubescape diff\"/--baseline. Works for posture reports (kubescape scan --format json), reporting new, resolved, unchanged, and incomparable control failures, and for image vulnerability reports (kubescape scan image --format json), reporting new, resolved, and unchanged CVEs. Both reports must be the same kind; comparing a posture report against a vulnerability report is rejected rather than silently treated as comparable."),
		mcp.WithString("base_report", mcp.Required(), mcp.Description("Path to the baseline/base Kubescape scan report JSON file")),
		mcp.WithString("head_report", mcp.Required(), mcp.Description("Path to the current/head Kubescape scan report JSON file")),
	)

	ksServer.s.AddTool(tool, func(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok || args == nil {
			args = map[string]any{}
		}

		baseReport, toolErr := mcpRequiredStringArg(args, "base_report")
		if toolErr != nil {
			return toolErr, nil
		}
		headReport, toolErr := mcpRequiredStringArg(args, "head_report")
		if toolErr != nil {
			return toolErr, nil
		}

		kind, postureChangeSet, vulnerabilityChangeSet, err := diff.CompareReports(baseReport, headReport, diff.Options{})
		if err != nil {
			if errors.Is(err, diff.ErrMixedReportKinds) {
				return mcpToolError(ErrCodeInvalidArgument, err.Error(), map[string]any{
					"base_report_kind": reportKindLabel(diff.ReportKindOf(baseReport)),
					"head_report_kind": reportKindLabel(diff.ReportKindOf(headReport)),
				}), nil
			}
			return mcpToolError(ErrCodeInvalidArgument, fmt.Sprintf("failed to compare reports: %v", err), nil), nil
		}

		result := diffReportsResult{
			Kind:          reportKindLabel(kind),
			BaseReport:    baseReport,
			HeadReport:    headReport,
			Posture:       postureChangeSet,
			Vulnerability: vulnerabilityChangeSet,
		}

		resBytes, err := jsonMarshal(result)
		if err != nil {
			return mcpToolError(ErrCodeMarshalError, fmt.Sprintf("failed to marshal result: %v", err), nil), nil
		}
		return mcp.NewToolResultStructured(result, string(resBytes)), nil
	})
}
