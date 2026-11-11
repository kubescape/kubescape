// Package remediationverify decides, from a fresh scan report, whether the
// findings a remediation set out to fix are fixed.
//
// It holds only the judgement: which resource and control of the report an item
// refers to, and what the control's status there allows to be concluded. It does
// not run a scan or write a file. Both the verify_remediation MCP tool and
// `kubescape fix --verify` call it, so that one rule decides what counts as
// resolved.
//
// An item is resolved only when it positively matches exactly one resource and
// exactly one control of that resource, the control is reported as passed with
// no sub-status, and the scan is known to be complete. Absence of any kind, of
// the resource, the control or a finding, never counts as resolution: a local
// IaC resource ID depends on the file path and the document's position, so a
// renamed, moved or reordered resource, or a different scan root, is not found
// in the fresh scan rather than fixed.
package remediationverify

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

// Verdict values for Result.Verdict.
const (
	VerdictResolved     = "resolved"
	VerdictStillFailing = "still_failing"
	VerdictUnverified   = "unverified"
)

// Reason codes for Result.Reason. resolved and still_failing carry the reason
// that states the evidence behind them; every other code accompanies an
// unverified verdict.
const (
	ReasonControlPassed        = "control_passed"
	ReasonControlFailed        = "control_failed"
	ReasonResourceIDMissing    = "resource_id_missing"
	ReasonResourceNotFound     = "resource_not_found"
	ReasonAmbiguousResource    = "ambiguous_resource"
	ReasonControlNotFound      = "control_not_found"
	ReasonAmbiguousControl     = "ambiguous_control"
	ReasonControlNotEvaluated  = "control_not_evaluated"
	ReasonControlSubStatus     = "control_substatus_present"
	ReasonControlStatusUnknown = "control_status_unknown"
	ReasonCoverageInsufficient = "scan_coverage_insufficient"
)

// Item is one finding to check: a control on a resource, by the resource ID the
// original report gave it.
type Item struct {
	ResourceID string
	ControlID  string
}

// Result is the verdict for the input item at Index.
type Result struct {
	Index      int    `json:"index"`
	ResourceID string `json:"resource_id"`
	ControlID  string `json:"control_id"`
	Verdict    string `json:"verdict"`
	Reason     string `json:"reason"`
	// Message explains an unverified verdict; it is empty otherwise.
	Message string `json:"message,omitempty"`
}

// Summary counts the verdicts of a Response.
type Summary struct {
	Resolved     int `json:"resolved"`
	StillFailing int `json:"still_failing"`
	Unverified   int `json:"unverified"`
}

// Response is the verdicts for a list of items.
type Response struct {
	// Results has one entry per input item, in input order.
	Results []Result `json:"results"`
	Summary Summary  `json:"summary"`
	// Degraded reports that the scan did not fully complete or carries no
	// coverage information. No item is resolved on such a scan.
	Degraded bool `json:"degraded"`
}

var unverifiedMessages = map[string]string{
	ReasonResourceIDMissing:    "the item has no resource_id, so there is no resource to look up",
	ReasonResourceNotFound:     "the resource_id is not in the fresh scan; the resource may have been renamed, moved, reordered or deleted, or path is a different root than the original scan, so this does not show the finding is fixed",
	ReasonAmbiguousResource:    "more than one result in the fresh scan has this resource_id",
	ReasonControlNotFound:      "the resource is in the fresh scan but the control was not reported for it",
	ReasonAmbiguousControl:     "the fresh scan reports this control more than once for the resource",
	ReasonControlNotEvaluated:  "the control was skipped or not fully evaluated in the fresh scan",
	ReasonControlSubStatus:     "the control passed with a sub-status, which is not a conclusive pass",
	ReasonControlStatusUnknown: "the control has a status that is neither passed nor failed",
	ReasonCoverageInsufficient: "the fresh scan did not fully complete or reports no coverage information, so a pass cannot be confirmed",
}

// Explanation says in words what a reason code means for a verdict. Unlike
// Result.Message, which only an unverified verdict carries, it also covers the
// reasons that accompany resolved and still_failing, for output that shows every
// verdict the same way.
func Explanation(reason string) string {
	switch reason {
	case ReasonControlPassed:
		return "the control passed in the fresh scan, which completed"
	case ReasonControlFailed:
		return "the control is still reported as failed in the fresh scan"
	}
	return unverifiedMessages[reason]
}

// NormalizeControlID is the form control IDs are compared in.
func NormalizeControlID(id string) string {
	return strings.ToUpper(strings.TrimSpace(id))
}

// ControlIDs returns the distinct control IDs of the items, normalized and
// sorted, which is the control set the fresh scan has to cover.
func ControlIDs(items []Item) []string {
	seen := make(map[string]bool, len(items))
	ids := make([]string, 0, len(items))
	for _, item := range items {
		id := NormalizeControlID(item.ControlID)
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// ReportJSON serializes a scan's report in the form ClassifyReportJSON reads: the
// posture report with a top-level scanCoverage that is always present.
//
// It is not the form ResultsHandler.ToJson writes. That one attaches the
// coverage only when it has gaps to show, so a scan that completed cleanly
// writes none, and a reader cannot tell a clean scan from one that reports
// nothing about itself. A pass is only confirmed on a scan known to be clean, so
// the verifier is given the coverage explicitly.
func ReportJSON(report *reporthandlingv2.PostureReport, coverage *cautils.ScanCoverage) ([]byte, error) {
	output := struct {
		*reporthandlingv2.PostureReport
		ScanCoverage *cautils.ScanCoverage `json:"scanCoverage,omitempty"`
	}{
		PostureReport: report,
		ScanCoverage:  coverage,
	}
	return json.Marshal(&output)
}

// ClassifyReportJSON classifies every item against a fresh scan's report in the
// form `kubescape scan --format json` writes: the posture report with a
// top-level scanCoverage. scanDegraded carries the scan's own degraded signal,
// which is wider than the coverage's because it includes rule-processing
// failures.
//
// A report that cannot be parsed is returned as an error; it is never turned
// into verdicts.
func ClassifyReportJSON(reportJSON []byte, scanDegraded bool, items []Item) (Response, error) {
	var report reporthandlingv2.PostureReport
	if err := json.Unmarshal(reportJSON, &report); err != nil {
		return Response{}, fmt.Errorf("failed to parse the fresh posture report: %w", err)
	}
	var envelope struct {
		ScanCoverage *cautils.ScanCoverage `json:"scanCoverage"`
	}
	if err := json.Unmarshal(reportJSON, &envelope); err != nil {
		return Response{}, fmt.Errorf("failed to parse the fresh posture report coverage: %w", err)
	}
	return Classify(&report, envelope.ScanCoverage, scanDegraded, items), nil
}

// Classify decides every item's verdict from the fresh report. It reads only
// the report, so it can be tested without a scan.
func Classify(report *reporthandlingv2.PostureReport, coverage *cautils.ScanCoverage, scanDegraded bool, items []Item) Response {
	resultsByID := make(map[string][]*resourcesresults.Result, len(report.Results))
	for i := range report.Results {
		r := &report.Results[i]
		resultsByID[r.ResourceID] = append(resultsByID[r.ResourceID], r)
	}

	notEvaluated := make(map[string]bool)
	if coverage != nil {
		for _, ne := range coverage.NotEvaluatedControls {
			notEvaluated[NormalizeControlID(ne.ControlID)] = true
		}
	}
	coverageComplete := coverage != nil && !scanDegraded && !coverage.Degraded &&
		len(coverage.FailedGVRPulls) == 0 && len(coverage.PartialGVRPulls) == 0 &&
		len(coverage.PolicyDegradations) == 0 && len(coverage.SkippedManifests) == 0

	resp := Response{
		Results:  make([]Result, 0, len(items)),
		Degraded: !coverageComplete,
	}
	for i, item := range items {
		verdict, reason := classifyItem(resultsByID, notEvaluated, coverageComplete, item)
		result := Result{
			Index:      i,
			ResourceID: item.ResourceID,
			ControlID:  item.ControlID,
			Verdict:    verdict,
			Reason:     reason,
		}
		if verdict == VerdictUnverified {
			result.Message = unverifiedMessages[reason]
		}
		resp.Results = append(resp.Results, result)
		switch verdict {
		case VerdictResolved:
			resp.Summary.Resolved++
		case VerdictStillFailing:
			resp.Summary.StillFailing++
		default:
			resp.Summary.Unverified++
		}
	}
	return resp
}

func classifyItem(resultsByID map[string][]*resourcesresults.Result, notEvaluated map[string]bool, coverageComplete bool, item Item) (verdict, reason string) {
	if item.ResourceID == "" {
		return VerdictUnverified, ReasonResourceIDMissing
	}
	matches := resultsByID[item.ResourceID]
	switch len(matches) {
	case 0:
		return VerdictUnverified, ReasonResourceNotFound
	case 1:
	default:
		return VerdictUnverified, ReasonAmbiguousResource
	}

	controlID := NormalizeControlID(item.ControlID)
	var control *resourcesresults.ResourceAssociatedControl
	found := 0
	for i := range matches[0].AssociatedControls {
		if NormalizeControlID(matches[0].AssociatedControls[i].ControlID) == controlID {
			control = &matches[0].AssociatedControls[i]
			found++
		}
	}
	switch found {
	case 0:
		return VerdictUnverified, ReasonControlNotFound
	case 1:
	default:
		return VerdictUnverified, ReasonAmbiguousControl
	}

	// The scan's own list of controls it could not evaluate comes first: a
	// control listed there has no conclusive result, whatever the report shows.
	if notEvaluated[controlID] {
		return VerdictUnverified, ReasonControlNotEvaluated
	}
	status := control.GetStatus(nil)
	subStatus := control.GetSubStatus()
	if subStatus == apis.SubStatusNotEvaluated || subStatus == apis.SubStatusIncompleteCoverage {
		return VerdictUnverified, ReasonControlNotEvaluated
	}

	switch status.Status() {
	case apis.StatusFailed:
		return VerdictStillFailing, ReasonControlFailed
	case apis.StatusPassed:
		if subStatus != apis.SubStatusUnknown {
			return VerdictUnverified, ReasonControlSubStatus
		}
		if !coverageComplete {
			return VerdictUnverified, ReasonCoverageInsufficient
		}
		return VerdictResolved, ReasonControlPassed
	case apis.StatusSkipped:
		return VerdictUnverified, ReasonControlNotEvaluated
	default:
		return VerdictUnverified, ReasonControlStatusUnknown
	}
}
