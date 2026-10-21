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
	Kind          string             `json:"kind"`
	BaseReport    string             `json:"base_report"`
	HeadReport    string             `json:"head_report"`
	Counts        diffReportsCounts  `json:"counts"`
	Posture       *postureDiff       `json:"posture,omitempty"`
	Vulnerability *vulnerabilityDiff `json:"vulnerability,omitempty"`
}

// diffReportsCounts gives the size of every bucket, so the caller knows how
// many unchanged findings there are even when the list itself is left out.
type diffReportsCounts struct {
	New          int `json:"new"`
	Resolved     int `json:"resolved"`
	Unchanged    int `json:"unchanged"`
	Incomparable int `json:"incomparable"`
}

// postureDiff and vulnerabilityDiff are the change sets as returned by the
// tool. The outer Unchanged field hides the embedded one when marshalled, and
// is nil (so left out) unless the caller asked for it: findings that failed
// in both reports usually outnumber the changes by far, and are rarely what
// the caller wants to read.
type postureDiff struct {
	*diff.ChangeSet
	Unchanged *[]diff.ControlChange `json:"unchanged,omitempty"`
}

type vulnerabilityDiff struct {
	*diff.VulnerabilityChangeSet
	Unchanged *[]diff.VulnerabilityChange `json:"unchanged,omitempty"`
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
		mcp.WithDescription("Compare two already-produced Kubescape scan report files (JSON) and return what changed, reusing the same comparison engine as \"kubescape diff\"/--baseline. Works for posture reports (kubescape scan --format json), reporting new, resolved, unchanged, and incomparable control failures, and for image vulnerability reports (kubescape scan image --format json), reporting new, resolved, and unchanged CVEs. Unchanged findings are only counted unless include_unchanged is true. Both reports must be the same kind; comparing a posture report against a vulnerability report is rejected rather than silently treated as comparable."),
		mcp.WithString("base_report", mcp.Required(), mcp.Description("Path to the baseline/base Kubescape scan report JSON file")),
		mcp.WithString("head_report", mcp.Required(), mcp.Description("Path to the current/head Kubescape scan report JSON file")),
		mcp.WithBoolean("include_unchanged", mcp.Description("Also list the findings that are the same in both reports (default false; counts.unchanged always gives their number)")),
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

		includeUnchanged, toolErr := mcpBoolArg(args, "include_unchanged")
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
			Kind:       reportKindLabel(kind),
			BaseReport: baseReport,
			HeadReport: headReport,
		}
		if postureChangeSet != nil {
			result.Counts = diffReportsCounts{
				New:          len(postureChangeSet.New),
				Resolved:     len(postureChangeSet.Resolved),
				Unchanged:    len(postureChangeSet.Unchanged),
				Incomparable: len(postureChangeSet.Incomparable),
			}
			result.Posture = &postureDiff{ChangeSet: postureChangeSet}
			if includeUnchanged {
				unchanged := append([]diff.ControlChange{}, postureChangeSet.Unchanged...)
				result.Posture.Unchanged = &unchanged
			}
		}
		if vulnerabilityChangeSet != nil {
			result.Counts = diffReportsCounts{
				New:       len(vulnerabilityChangeSet.New),
				Resolved:  len(vulnerabilityChangeSet.Resolved),
				Unchanged: len(vulnerabilityChangeSet.Unchanged),
			}
			result.Vulnerability = &vulnerabilityDiff{VulnerabilityChangeSet: vulnerabilityChangeSet}
			if includeUnchanged {
				unchanged := append([]diff.VulnerabilityChange{}, vulnerabilityChangeSet.Unchanged...)
				result.Vulnerability.Unchanged = &unchanged
			}
		}

		resBytes, err := jsonMarshal(result)
		if err != nil {
			return mcpToolError(ErrCodeMarshalError, fmt.Sprintf("failed to marshal result: %v", err), nil), nil
		}
		return mcp.NewToolResultStructured(result, string(resBytes)), nil
	})
}
