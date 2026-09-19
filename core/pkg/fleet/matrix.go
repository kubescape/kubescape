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
// Two clusters can describe the same control differently, most often when they
// were scanned against different control library versions, so a row's Name and
// Severity are settled by value rather than by whichever cluster was read
// first. Any rule is arbitrary once they disagree, and the matrix does not try
// to reconcile the definitions behind them, but it must not answer differently
// depending on the order the clusters happened to be scanned in. The highest
// score factor wins, so a row never reports a control as milder than some
// cluster rated it, and an equal score factor is settled on the name.
func BuildControlMatrix(results []ClusterResult) FleetControlMatrix {
	rows := make(map[string]*FleetControlRow)
	descriptions := make(map[string]controlDescription)

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
					ByCluster: make(map[string]ControlStatusCell),
				}
				rows[controlID] = row
			}
			if describes, ok := descriptions[controlID]; !ok || describes.losesTo(summary.GetScoreFactor(), summary.GetName()) {
				descriptions[controlID] = controlDescription{
					scoreFactor: summary.GetScoreFactor(),
					name:        summary.GetName(),
				}
			}
			cell := newControlStatusCell(&summary)
			if existing, ok := row.ByCluster[cluster.ClusterID]; ok &&
				outcomeRank(existing.Status) >= outcomeRank(cell.Status) {
				// Two results carrying the same cluster ID describe one
				// cluster, so the cell has to resolve to one of them by value
				// rather than by whichever arrived last. The worse outcome
				// wins: a cell reading passed while one of the results said
				// failed would hide the finding.
				continue
			}
			row.ByCluster[cluster.ClusterID] = cell
		}
	}

	controls := make([]FleetControlRow, 0, len(rows))
	for controlID, row := range rows {
		row.Name = descriptions[controlID].name
		row.Severity = apis.ControlSeverityToString(descriptions[controlID].scoreFactor)
		controls = append(controls, *row)
	}
	sort.Slice(controls, func(i, j int) bool {
		return controls[i].ControlID < controls[j].ControlID
	})

	return FleetControlMatrix{Controls: controls}
}

// controlDescription is how one cluster described a control, kept so a row can
// settle on one description by value once the clusters disagree.
type controlDescription struct {
	scoreFactor float32
	name        string
}

// losesTo reports whether this description gives way to the candidate one. The
// higher score factor wins, and an equal score factor is settled on the name so
// the result never depends on scan order.
func (d controlDescription) losesTo(scoreFactor float32, name string) bool {
	if scoreFactor != d.scoreFactor {
		return scoreFactor > d.scoreFactor
	}
	return name < d.name
}

// outcomeRank orders the cell outcomes from most to least alarming, so that a
// cluster reported more than once resolves to its worst outcome rather than to
// whichever result happened to be read last.
func outcomeRank(status CellStatus) int {
	switch status {
	case CellFailed:
		return 3
	case CellNotEvaluated:
		return 2
	case CellSkipped:
		return 1
	case CellPassed:
		return 0
	default:
		return 0
	}
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
