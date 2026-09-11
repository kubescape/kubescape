package fleet

import (
	"sort"

	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

// BuildControlMatrix builds the control x cluster grid from per-cluster results.
//
// Only clusters with ClusterScanned status and a non-nil Report contribute
// cells. Everything else is skipped rather than represented as a zero value:
// an unreachable cluster has no opinion about whether a control passes, and
// recording one as "passed" or as an empty status would let a cluster nobody
// could reach silently improve the fleet's apparent posture.
//
// Rows are sorted by control ID. Control summaries come out of a map, so
// without sorting the same fleet would render its rows in a different order on
// every run and two JSON reports of an unchanged fleet would not compare equal.
//
// A row's Name and Severity are taken from the first scanned cluster that
// reports the control, which is deterministic because results is a slice. Two
// clusters could in principle disagree on either, for instance when they were
// scanned against different control versions, and the first one wins. That is
// deliberate: the matrix reports what each cluster found rather than trying to
// reconcile the definitions behind it.
func BuildControlMatrix(results []ClusterResult) FleetControlMatrix {
	rows := make(map[string]*FleetControlRow)

	for i := range results {
		cluster := &results[i]
		if !cluster.Scanned() {
			continue
		}

		controls := cluster.Report.SummaryDetails.Controls
		for controlID := range controls {
			// The summary is copied out of the map on purpose. Reading a
			// control's status mutates it: GetStatus fills StatusInfo in from
			// the legacy Status field when StatusInfo is empty. Working on a
			// copy keeps that write off the caller's report, so building a
			// matrix leaves the reports it was built from untouched.
			summary := controls[controlID]

			row, ok := rows[controlID]
			if !ok {
				row = &FleetControlRow{
					ControlID: controlID,
					Name:      summary.GetName(),
					Severity:  apis.ControlSeverityToString(summary.GetScoreFactor()),
					ByCluster: make(map[string]ControlStatusCell),
				}
				rows[controlID] = row
			}
			row.ByCluster[cluster.ClusterID] = newControlStatusCell(&summary)
		}
	}

	controls := make([]FleetControlRow, 0, len(rows))
	for _, row := range rows {
		controls = append(controls, *row)
	}
	sort.Slice(controls, func(i, j int) bool {
		return controls[i].ControlID < controls[j].ControlID
	})

	return FleetControlMatrix{Controls: controls}
}

// newControlStatusCell reads one control summary into a cell.
//
// It takes a pointer because every getter on ControlSummary has a pointer
// receiver, and GetStatus in particular writes back: when StatusInfo carries no
// status it fills it in from the legacy Status field. The pointer therefore has
// to address a copy rather than anything the caller keeps. BuildControlMatrix
// passes the loop variable, which Go gives a fresh address on each iteration
// and which is already a copy of the map value, so the write-back stays inside
// this function and the caller's report is never modified.
func newControlStatusCell(summary *reportsummary.ControlSummary) ControlStatusCell {
	return ControlStatusCell{
		Status:          cellStatus(summary),
		FailedResources: summary.NumberOfResources().Failed(),
		ComplianceScore: summary.GetComplianceScore(),
	}
}

// cellStatus normalises a control summary into a CellStatus, separating a
// control that was skipped on purpose from one that never reached a verdict.
//
// Only a genuine skip can be deliberate, and even then the sub-status decides:
// OPAProcessor.markControlsSkipped writes skipped with a notEvaluated
// sub-status for a control that could not run, which is a coverage gap rather
// than a decision.
//
// Everything that reached no verdict at all maps to CellNotEvaluated, not to
// CellSkipped. That covers a control whose status was never set, and the
// deprecated "error" status. Calling either of those skipped would assert a
// deliberate exclusion nobody chose, and would hide the gap behind a value that
// compares equal to a real skip on another cluster, which is the exact
// confusion CellStatus exists to prevent. The deprecated "excluded" and
// "irrelevant" spellings are genuine non-application and stay skipped.
func cellStatus(summary *reportsummary.ControlSummary) CellStatus {
	status := summary.GetStatus()

	switch {
	case status.IsPassed():
		return CellPassed
	case status.IsFailed():
		return CellFailed
	case status.IsSkipped():
		if status.GetSubStatus() == apis.SubStatusNotEvaluated {
			return CellNotEvaluated
		}
		return CellSkipped
	case status.Status() == apis.StatusExcluded, status.Status() == apis.StatusIrrelevant:
		return CellSkipped
	default:
		return CellNotEvaluated
	}
}
