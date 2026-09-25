package fleet

import (
	"slices"
	"sort"
	"strings"
)

// FleetDivergence lists the controls the fleet does not agree on.
//
// The matrix already says what every cluster found, but most of it is clusters
// agreeing, which sends nobody anywhere. This keeps only the rows where they
// pull apart, so a fleet of thirty clusters that agree on all but two controls
// produces two rows instead of a grid to read.
type FleetDivergence struct {
	// ReferenceCluster is the cluster the others are read against, empty when
	// none was asked for.
	//
	// Naming one does not change which controls appear, because clusters either
	// disagree or they do not, and the reference is one of them. What it adds
	// is the reference's own verdict on every row, so somebody comparing
	// against a cluster they trust sees what it found beside everyone else.
	ReferenceCluster string `json:"referenceCluster,omitempty"`
	// ReferenceUnavailable is set when a reference cluster was asked for but
	// contributed nothing to the matrix, so there is no verdict of its own to
	// read the others against. The rows are still reported, since the clusters
	// still disagree, and each carries no reference status.
	ReferenceUnavailable bool `json:"referenceUnavailable,omitempty"`
	// Controls is sorted by control ID, and absent when the fleet agrees
	// everywhere.
	Controls []ControlDivergence `json:"controls,omitempty"`
}

// ControlDivergence is one control the clusters do not agree on, with the
// clusters grouped by what each of them found.
//
// The two flags split the kinds of disagreement, which is the distinction this
// whole package is built around. Clusters reaching different verdicts is a real
// difference in posture worth investigating. A cluster that could not evaluate
// the control is a gap in what was measured and says nothing about posture in
// either direction. Both can be true at once, and neither being true means the
// clusters differ only in whether the control was applied to them at all, which
// shows up in Skipped.
type ControlDivergence struct {
	ControlID string `json:"controlID"`
	Name      string `json:"name"`
	Severity  string `json:"severity"`
	// PostureDiverges is set when one cluster passed the control and another
	// failed it. That is a real difference between the clusters.
	PostureDiverges bool `json:"postureDiverges"`
	// CoverageGap is set when a cluster could not evaluate the control while
	// another cluster produced some outcome for it, whether that was a verdict
	// or a decision to skip it. However the rest of the row looks, part of the
	// fleet was not measured here.
	CoverageGap bool `json:"coverageGap"`
	// ReferenceStatus is what the reference cluster found. Omitted when no
	// reference was asked for, and when the reference has no cell for this
	// control, which is itself worth seeing: the cluster being compared against
	// did not look at something the others did.
	ReferenceStatus CellStatus `json:"referenceStatus,omitempty"`
	// Passed, Failed, Skipped and NotEvaluated hold the clusters at each
	// outcome, each sorted by cluster ID. A cluster that contributed no cell
	// for this control appears in none of them.
	Passed       []string `json:"passed,omitempty"`
	Failed       []string `json:"failed,omitempty"`
	Skipped      []string `json:"skipped,omitempty"`
	NotEvaluated []string `json:"notEvaluated,omitempty"`
}

// BuildDivergence finds the controls the clusters disagree on.
//
// It reads the matrix rather than the cluster results, so what it reports and
// what the matrix shows cannot drift apart. A control is reported when the
// clusters that contributed a cell for it did not all reach the same outcome.
// Controls everyone agreed on are left out, including the ones nobody could
// evaluate: a fleet that uniformly failed to measure something has a coverage
// problem rather than a disagreement, and the matrix already shows it.
//
// referenceCluster is optional and names the cluster the others are read
// against. It is not required to have been scanned, and one that was asked for
// but contributed nothing is reported through ReferenceUnavailable rather than
// silently ignored. Surrounding whitespace is trimmed, so a caller passing a
// blank string is treated as asking for no reference rather than for a cluster
// whose name is a space, which would be reported as unavailable and read as an
// infrastructure problem.
func BuildDivergence(matrix FleetControlMatrix, referenceCluster string) FleetDivergence {
	reference := strings.TrimSpace(referenceCluster)
	divergence := FleetDivergence{
		ReferenceCluster:     reference,
		ReferenceUnavailable: reference != "" && !clusterInMatrix(matrix, reference),
	}

	for i := range matrix.Controls {
		row := &matrix.Controls[i]

		control := ControlDivergence{
			ControlID: row.ControlID,
			Name:      row.Name,
			Severity:  row.Severity,
		}
		for clusterID, cell := range row.ByCluster {
			switch cell.Status {
			case CellPassed:
				control.Passed = append(control.Passed, clusterID)
			case CellFailed:
				control.Failed = append(control.Failed, clusterID)
			case CellSkipped:
				control.Skipped = append(control.Skipped, clusterID)
			case CellNotEvaluated:
				control.NotEvaluated = append(control.NotEvaluated, clusterID)
			}
		}

		if outcomesRepresented(&control) < 2 {
			continue
		}

		control.PostureDiverges = len(control.Passed) > 0 && len(control.Failed) > 0
		control.CoverageGap = len(control.NotEvaluated) > 0 &&
			len(control.Passed)+len(control.Failed)+len(control.Skipped) > 0

		if cell, ok := row.ByCluster[reference]; ok && reference != "" {
			control.ReferenceStatus = cell.Status
		}

		// Gathered from a map, so sorted here for the same reason the matrix
		// sorts its rows: without it two reports of an unchanged fleet would
		// not compare equal.
		slices.Sort(control.Passed)
		slices.Sort(control.Failed)
		slices.Sort(control.Skipped)
		slices.Sort(control.NotEvaluated)

		divergence.Controls = append(divergence.Controls, control)
	}

	sort.SliceStable(divergence.Controls, func(i, j int) bool {
		return divergence.Controls[i].ControlID < divergence.Controls[j].ControlID
	})

	return divergence
}

// clusterInMatrix reports whether the cluster contributed a cell anywhere in
// the matrix, which is what makes it usable as a reference.
func clusterInMatrix(matrix FleetControlMatrix, clusterID string) bool {
	for i := range matrix.Controls {
		if _, ok := matrix.Controls[i].ByCluster[clusterID]; ok {
			return true
		}
	}
	return false
}

// outcomesRepresented counts how many distinct outcomes the clusters reached on
// one control. Fewer than two means they agreed.
func outcomesRepresented(control *ControlDivergence) int {
	represented := 0
	for _, clusters := range [][]string{
		control.Passed, control.Failed, control.Skipped, control.NotEvaluated,
	} {
		if len(clusters) > 0 {
			represented++
		}
	}
	return represented
}
