package mcpserver

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

// Verdict values for verifyResult.Verdict.
const (
	verdictResolved     = "resolved"
	verdictStillFailing = "still_failing"
	verdictUnverified   = "unverified"
)

// Reason codes for verifyResult.Reason. resolved and still_failing carry the
// reason that states the evidence behind them; every other code accompanies an
// unverified verdict.
const (
	reasonControlPassed        = "control_passed"
	reasonControlFailed        = "control_failed"
	reasonResourceIDMissing    = "resource_id_missing"
	reasonResourceNotFound     = "resource_not_found"
	reasonAmbiguousResource    = "ambiguous_resource"
	reasonControlNotFound      = "control_not_found"
	reasonAmbiguousControl     = "ambiguous_control"
	reasonControlNotEvaluated  = "control_not_evaluated"
	reasonControlSubStatus     = "control_substatus_present"
	reasonControlStatusUnknown = "control_status_unknown"
	reasonCoverageInsufficient = "scan_coverage_insufficient"
)

// maxVerifyItems bounds the items one call verifies, so a single request cannot
// make the response unbounded.
const maxVerifyItems = 1000

// verifyItem is the part of one apply_remediation item the verifier reads. The
// caller passes apply_remediation's items unchanged; every other field of an
// item is ignored.
type verifyItem struct {
	ResourceID string
	ControlID  string
}

// verifyResult is the verdict for the input item at Index.
type verifyResult struct {
	Index      int    `json:"index"`
	ResourceID string `json:"resource_id"`
	ControlID  string `json:"control_id"`
	Verdict    string `json:"verdict"`
	Reason     string `json:"reason"`
	// Message explains an unverified verdict; it is empty otherwise.
	Message string `json:"message,omitempty"`
}

type verifySummary struct {
	Resolved     int `json:"resolved"`
	StillFailing int `json:"still_failing"`
	Unverified   int `json:"unverified"`
}

type verifyResponse struct {
	// Results has one entry per input item, in input order.
	Results []verifyResult `json:"results"`
	Summary verifySummary  `json:"summary"`
	// Degraded reports that the scan did not fully complete or carries no
	// coverage information, mirroring scanResponse.Degraded. No item is
	// resolved on such a scan.
	Degraded bool `json:"degraded"`
}

var unverifiedMessages = map[string]string{
	reasonResourceIDMissing:    "the item has no resource_id, so there is no resource to look up",
	reasonResourceNotFound:     "the resource_id is not in the fresh scan; the resource may have been renamed, moved, reordered or deleted, or path is a different root than the original scan, so this does not show the finding is fixed",
	reasonAmbiguousResource:    "more than one result in the fresh scan has this resource_id",
	reasonControlNotFound:      "the resource is in the fresh scan but the control was not reported for it",
	reasonAmbiguousControl:     "the fresh scan reports this control more than once for the resource",
	reasonControlNotEvaluated:  "the control was skipped or not fully evaluated in the fresh scan",
	reasonControlSubStatus:     "the control passed with a sub-status, which is not a conclusive pass",
	reasonControlStatusUnknown: "the control has a status that is neither passed nor failed",
	reasonCoverageInsufficient: "the fresh scan did not fully complete or reports no coverage information, so a pass cannot be confirmed",
}

func createVerifyRemediationTools(ksServer *KubescapeMcpserver) {
	verifyRemediationTool := mcp.NewTool(
		"verify_remediation",
		mcp.WithDescription("Check whether findings listed by apply_remediation are fixed, after the caller has applied the changes to local IaC. Rescans path once and returns one verdict per item, in input order: resolved only when the original resource is found in the fresh scan and the control is reported as passed with a complete scan; still_failing when the control is reported as failed; unverified, with a reason code, whenever that cannot be established. A missing resource or control is never a resolution: IaC resource IDs depend on the file path relative to the scan root and the document's position in its file, so a renamed or moved file, a reordered document or a different path root all show up as resource_not_found. Read-only: it does not apply patches or modify any file."),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("The same local YAML file or directory root that was passed to apply_remediation, now holding the applied changes."),
		),
		mcp.WithArray("items",
			mcp.Required(),
			mcp.Items(map[string]any{
				"type": "object",
				"properties": map[string]any{
					"resource_id": map[string]any{"type": "string"},
					"control": map[string]any{
						"type":       "object",
						"properties": map[string]any{"id": map[string]any{"type": "string"}},
						"required":   []string{"id"},
					},
				},
				"required": []string{"resource_id", "control"},
			}),
			mcp.Description("The items array returned by apply_remediation, passed unchanged. Only resource_id and control.id are read. Items without a resource_id (not_evaluated items) are returned as unverified."),
		),
	)
	ksServer.s.AddTool(verifyRemediationTool, ksServer.toolHandler(verifyRemediationTool.Name))
}

// parseVerifyItems decodes the items argument. A malformed item fails the whole
// call rather than being dropped, so the output always lines up with the input.
func parseVerifyItems(arguments map[string]any) ([]verifyItem, *mcp.CallToolResult) {
	raw, present := arguments["items"]
	if !present || raw == nil {
		return nil, mcpToolError(ErrCodeInvalidArgument, "items argument is required", map[string]any{"argument": "items"})
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, mcpToolError(ErrCodeInvalidArgument, "items must be an array", map[string]any{"argument": "items"})
	}
	if len(list) > maxVerifyItems {
		return nil, mcpToolError(ErrCodeInvalidArgument, fmt.Sprintf("items has %d entries, more than the limit of %d", len(list), maxVerifyItems), map[string]any{"argument": "items"})
	}

	items := make([]verifyItem, len(list))
	for i, entry := range list {
		obj, ok := entry.(map[string]any)
		if !ok {
			return nil, invalidVerifyItem(i, "must be an object")
		}
		resourceID, ok := obj["resource_id"].(string)
		if !ok {
			return nil, invalidVerifyItem(i, "resource_id must be a string")
		}
		control, ok := obj["control"].(map[string]any)
		if !ok {
			return nil, invalidVerifyItem(i, "control must be an object")
		}
		controlID, ok := control["id"].(string)
		if !ok || strings.TrimSpace(controlID) == "" {
			return nil, invalidVerifyItem(i, "control.id must be a non-empty string")
		}
		items[i] = verifyItem{ResourceID: resourceID, ControlID: strings.TrimSpace(controlID)}
	}
	return items, nil
}

func invalidVerifyItem(index int, problem string) *mcp.CallToolResult {
	return mcpToolError(ErrCodeInvalidArgument,
		fmt.Sprintf("items[%d]: %s", index, problem),
		map[string]any{"argument": "items", "index": index})
}

// verifyScanKey is the in-flight coalescing key of the scan behind one
// verify_remediation call. The scan depends only on the path and the controls;
// the verdicts are computed per caller afterwards.
func verifyScanKey(path string, controlIDs []string) string {
	return fmt.Sprintf("verify_remediation:%s:%s", url.QueryEscape(path), url.QueryEscape(strings.Join(controlIDs, ",")))
}

// verifyControlIDs returns the distinct control IDs of the items, normalized
// and sorted, which is the control set the fresh scan has to cover.
func verifyControlIDs(items []verifyItem) []string {
	seen := make(map[string]bool, len(items))
	ids := make([]string, 0, len(items))
	for _, item := range items {
		id := normalizeControlID(item.ControlID)
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// verifyRemediationReport classifies every item against the fresh scan's
// report. A report that cannot be parsed is returned as an error; it is never
// turned into verdicts.
func verifyRemediationReport(outcome *iacScanOutcome, items []verifyItem) ([]byte, error) {
	var report reporthandlingv2.PostureReport
	if err := json.Unmarshal(outcome.ReportJSON, &report); err != nil {
		return nil, fmt.Errorf("failed to parse the fresh posture report: %w", err)
	}
	var envelope struct {
		ScanCoverage *cautils.ScanCoverage `json:"scanCoverage"`
	}
	if err := json.Unmarshal(outcome.ReportJSON, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse the fresh posture report coverage: %w", err)
	}

	resp := classifyVerifyItems(&report, envelope.ScanCoverage, outcome.Degraded, items)
	return json.MarshalIndent(resp, "", "  ")
}

// classifyVerifyItems decides every item's verdict from the fresh report. It
// reads only the report, so it can be tested without a scan.
//
// An item is resolved only when it positively matches exactly one resource and
// exactly one control of that resource, the control is reported as passed with
// no sub-status, and the scan is known to be complete. Absence of any kind --
// of the resource, the control or a finding -- never counts as resolution.
// scanDegraded carries the scan's own degraded signal, which is wider than
// coverage.Degraded because it includes rule-processing failures.
func classifyVerifyItems(report *reporthandlingv2.PostureReport, coverage *cautils.ScanCoverage, scanDegraded bool, items []verifyItem) verifyResponse {
	resultsByID := make(map[string][]*resourcesresults.Result, len(report.Results))
	for i := range report.Results {
		r := &report.Results[i]
		resultsByID[r.ResourceID] = append(resultsByID[r.ResourceID], r)
	}

	notEvaluated := make(map[string]bool)
	if coverage != nil {
		for _, ne := range coverage.NotEvaluatedControls {
			notEvaluated[normalizeControlID(ne.ControlID)] = true
		}
	}
	coverageComplete := coverage != nil && !scanDegraded && !coverage.Degraded &&
		len(coverage.FailedGVRPulls) == 0 && len(coverage.PartialGVRPulls) == 0 &&
		len(coverage.PolicyDegradations) == 0 && len(coverage.SkippedManifests) == 0

	resp := verifyResponse{
		Results:  make([]verifyResult, 0, len(items)),
		Degraded: !coverageComplete,
	}
	for i, item := range items {
		verdict, reason := classifyVerifyItem(resultsByID, notEvaluated, coverageComplete, item)
		result := verifyResult{
			Index:      i,
			ResourceID: item.ResourceID,
			ControlID:  item.ControlID,
			Verdict:    verdict,
			Reason:     reason,
		}
		if verdict == verdictUnverified {
			result.Message = unverifiedMessages[reason]
		}
		resp.Results = append(resp.Results, result)
		switch verdict {
		case verdictResolved:
			resp.Summary.Resolved++
		case verdictStillFailing:
			resp.Summary.StillFailing++
		default:
			resp.Summary.Unverified++
		}
	}
	return resp
}

func classifyVerifyItem(resultsByID map[string][]*resourcesresults.Result, notEvaluated map[string]bool, coverageComplete bool, item verifyItem) (verdict, reason string) {
	if item.ResourceID == "" {
		return verdictUnverified, reasonResourceIDMissing
	}
	matches := resultsByID[item.ResourceID]
	switch len(matches) {
	case 0:
		return verdictUnverified, reasonResourceNotFound
	case 1:
	default:
		return verdictUnverified, reasonAmbiguousResource
	}

	controlID := normalizeControlID(item.ControlID)
	var control *resourcesresults.ResourceAssociatedControl
	found := 0
	for i := range matches[0].AssociatedControls {
		if normalizeControlID(matches[0].AssociatedControls[i].ControlID) == controlID {
			control = &matches[0].AssociatedControls[i]
			found++
		}
	}
	switch found {
	case 0:
		return verdictUnverified, reasonControlNotFound
	case 1:
	default:
		return verdictUnverified, reasonAmbiguousControl
	}

	// The scan's own list of controls it could not evaluate comes first: a
	// control listed there has no conclusive result, whatever the report shows.
	if notEvaluated[controlID] {
		return verdictUnverified, reasonControlNotEvaluated
	}
	status := control.GetStatus(nil)
	subStatus := control.GetSubStatus()
	if subStatus == apis.SubStatusNotEvaluated || subStatus == apis.SubStatusIncompleteCoverage {
		return verdictUnverified, reasonControlNotEvaluated
	}

	switch status.Status() {
	case apis.StatusFailed:
		return verdictStillFailing, reasonControlFailed
	case apis.StatusPassed:
		if subStatus != apis.SubStatusUnknown {
			return verdictUnverified, reasonControlSubStatus
		}
		if !coverageComplete {
			return verdictUnverified, reasonCoverageInsufficient
		}
		return verdictResolved, reasonControlPassed
	case apis.StatusSkipped:
		return verdictUnverified, reasonControlNotEvaluated
	default:
		return verdictUnverified, reasonControlStatusUnknown
	}
}
