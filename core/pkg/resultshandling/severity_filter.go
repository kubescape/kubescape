package resultshandling

import (
	"strings"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
)

// ApplySeverityFilters removes controls from the OPASessionObj that fall outside the
// [minSeverity, maxSeverity] range. Both bounds are inclusive. An empty string
// disables that bound. Controls removed here are also removed from every
// per-resource associated-control list so the report stays consistent.
func ApplySeverityFilters(sessionObj *cautils.OPASessionObj, minSeverity, maxSeverity string) {
	if sessionObj == nil || sessionObj.Report == nil {
		return
	}
	if minSeverity == "" && maxSeverity == "" {
		return
	}

	minRank := severityRankFromString(minSeverity)
	maxRank := apis.SeverityCritical
	if maxSeverity != "" {
		maxRank = severityRankFromString(maxSeverity)
	}

	retained := make(map[string]struct{}, len(sessionObj.Report.SummaryDetails.Controls))
	for id, control := range sessionObj.Report.SummaryDetails.Controls {
		rank := apis.ControlSeverityToInt(control.GetScoreFactor())
		if rank == apis.SeverityUnknown || rank < minRank || rank > maxRank {
			delete(sessionObj.Report.SummaryDetails.Controls, id)
		} else {
			retained[id] = struct{}{}
		}
	}

	for id, result := range sessionObj.ResourcesResult {
		ac := make([]resourcesresults.ResourceAssociatedControl, 0, len(result.AssociatedControls))
		for _, ctrl := range result.AssociatedControls {
			if _, ok := retained[ctrl.GetID()]; ok {
				ac = append(ac, ctrl)
			}
		}
		result.AssociatedControls = ac
		sessionObj.ResourcesResult[id] = result
	}

	recomputeSummaryDetails(sessionObj)
}

// recomputeSummaryDetails refreshes every derived summary field that was
// computed against the full control set before severity filtering. After
// ApplySeverityFilters removes lower-severity controls, the compliance score,
// framework compliance scores and severity counters would otherwise describe
// controls that are no longer present in the report. The risk score
// (SummaryDetails.Score) is deliberately left unrecomputed: it is a
// WCS-weighted aggregate whose weights are not available at filter time, so a
// plain average would not reproduce it.
func recomputeSummaryDetails(sessionObj *cautils.OPASessionObj) {
	if sessionObj == nil || sessionObj.Report == nil {
		return
	}
	summary := &sessionObj.Report.SummaryDetails

	var complianceSum float32
	count := 0
	for _, ctrl := range summary.Controls {
		complianceSum += ctrl.GetComplianceScore()
		count++
	}
	if count > 0 {
		summary.ComplianceScore = complianceSum / float32(count)
	} else {
		summary.ComplianceScore = 0
	}

	for i := range summary.Frameworks {
		var fSum float32
		fCount := 0
		for id, ctrl := range summary.Frameworks[i].Controls {
			if _, ok := summary.Controls[id]; ok {
				fSum += ctrl.GetComplianceScore()
				fCount++
			}
		}
		if fCount > 0 {
			summary.Frameworks[i].ComplianceScore = fSum / float32(fCount)
		} else {
			summary.Frameworks[i].ComplianceScore = 0
		}
	}

	summary.ControlsSeverityCounters = reportsummary.SeverityCounters{}
	for _, ctrl := range summary.Controls {
		if ctrl.GetStatus().IsFailed() {
			summary.ControlsSeverityCounters.Increase(apis.ControlSeverityToString(ctrl.GetScoreFactor()), 1)
		}
	}

	summary.ResourcesSeverityCounters = reportsummary.SeverityCounters{}
	for _, result := range sessionObj.ResourcesResult {
		if !result.GetStatus(nil).IsFailed() {
			continue
		}
		for _, ac := range result.AssociatedControls {
			if !ac.GetStatus(nil).IsFailed() {
				continue
			}
			if ctrl, ok := summary.Controls[ac.GetID()]; ok {
				summary.ResourcesSeverityCounters.Increase(apis.ControlSeverityToString(ctrl.GetScoreFactor()), 1)
			}
		}
	}
}

// severityRankFromString maps a user-supplied severity string to the same
// integer ordinal that apis.ControlSeverityToInt uses for score-based conversion,
// so the two can be compared directly. Unknown or empty values map to
// apis.SeverityUnknown (0), which is intentionally excluded when any lower
// bound filter is active.
func severityRankFromString(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case strings.ToLower(apis.SeverityCriticalString):
		return apis.SeverityCritical
	case strings.ToLower(apis.SeverityHighString):
		return apis.SeverityHigh
	case strings.ToLower(apis.SeverityMediumString):
		return apis.SeverityMedium
	case strings.ToLower(apis.SeverityLowString):
		return apis.SeverityLow
	default:
		return apis.SeverityUnknown
	}
}
