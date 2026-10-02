package printer

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/jwalton/gchalk"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/fleet"
)

// notMeasured is what a column shows when a cluster produced no figure for it.
// A dash rather than a zero, for the same reason the report leaves the field
// absent: a cluster nobody could reach is not a cluster scoring nothing.
const notMeasured = "-"

// PrintFleetReport writes the summary an operator reads after a multi-context
// scan: how each cluster did, how the fleet did, and where the clusters
// disagree.
//
// It is deliberately not an IPrinter. That interface takes one cluster's
// OPASessionObj, which a fleet report is not and cannot be made into, so
// implementing it would mean pretending a fleet is a cluster. What is shared
// instead is everything below the interface: the table style, the severity
// colours and the display helpers, so a fleet summary looks like the rest of
// Kubescape without a second copy of how that look is produced.
//
// The control matrix is not printed. It is one column per cluster and stops
// being readable somewhere around five of them, and it is already in the JSON
// for anyone who wants it.
func PrintFleetReport(w io.Writer, report *fleet.FleetReport) {
	if report == nil {
		return
	}

	cautils.InfoTextDisplay(w, "\nFleet summary\n")
	printFleetClusters(w, report)
	printFleetCompliance(w, &report.Compliance)
	printFleetDivergence(w, &report.Divergence, comparability(&report.ControlMatrix))
}

// printFleetClusters lists every context the run was asked for, including the
// ones that produced nothing. A cluster missing from the table would make the
// fleet look smaller and healthier than it is.
func printFleetClusters(w io.Writer, report *fleet.FleetReport) {
	if len(report.Clusters) == 0 {
		cautils.SimpleDisplay(w, "No clusters were scanned.\n\n")
		return
	}

	clusters := newFleetTable(w)
	clusters.AppendHeader(table.Row{"Cluster", "Status", "Compliance", "Coverage", "Duration"})

	for i := range report.Clusters {
		cluster := &report.Clusters[i]
		clusters.AppendRow(table.Row{
			cluster.ClusterID,
			fleetStatusText(cluster.Status),
			percentOrDash(cluster.ComplianceScore),
			fleetCoverageText(cluster),
			valueOrDash(cluster.Duration),
		})
	}
	clusters.Render()
	cautils.SimpleDisplay(w, "\n")

	// Errors sit under the table rather than in a column, because the reason a
	// cluster could not be scanned is a sentence and a column would truncate it
	// to uselessness.
	for i := range report.Clusters {
		cluster := &report.Clusters[i]
		if cluster.Error != "" {
			cautils.SimpleDisplay(w, "  %s: %s\n", cluster.ClusterID, cluster.Error)
		}
	}
}

// printFleetCompliance shows the fleet score beside the number of clusters it
// came from, and names the ones held out. A score with no basis printed next to
// it invites more confidence than it has earned.
func printFleetCompliance(w io.Writer, rollup *fleet.ComplianceRollup) {
	cautils.SimpleDisplay(w, "\nFleet compliance: %s  (from %d of %d clusters)\n",
		gchalk.WithBrightWhite().Bold(percentOrDash(rollup.ComplianceScore)),
		rollup.ClustersScored, rollup.ClustersTotal)

	if len(rollup.Frameworks) > 0 {
		frameworks := newFleetTable(w)
		frameworks.AppendHeader(table.Row{"Framework", "Compliance", "Clusters"})
		for i := range rollup.Frameworks {
			framework := &rollup.Frameworks[i]
			clusters := fmt.Sprintf("%d of %d", framework.ClustersScored, framework.ClustersReporting)
			if len(framework.VacuousIn) > 0 {
				clusters += fmt.Sprintf(" (%d vacuous)", len(framework.VacuousIn))
			}
			frameworks.AppendRow(table.Row{
				framework.Name, percentOrDash(framework.ComplianceScore), clusters,
			})
		}
		cautils.SimpleDisplay(w, "\n")
		frameworks.Render()
	}

	if len(rollup.Excluded) > 0 {
		cautils.SimpleDisplay(w, "\n")
		for i := range rollup.Excluded {
			excluded := &rollup.Excluded[i]
			cautils.SimpleDisplay(w, "  %s was not counted: %s\n",
				excluded.ClusterID, exclusionText(excluded, rollup.MinCoverage))
		}
	}
	cautils.SimpleDisplay(w, "\n")
}

// printFleetDivergence shows the controls the clusters did not agree on, worst
// severity first, so the row worth reading is the one at the top.
func printFleetDivergence(w io.Writer, divergence *fleet.FleetDivergence, compared matrixComparability) {
	// Ahead of the agreement case on purpose. A reference that produced nothing
	// is worth saying whether or not the clusters went on to disagree, and it is
	// least obvious in the run that otherwise looks like a clean bill of health.
	if divergence.ReferenceUnavailable {
		cautils.WarningDisplay(w, "Reference cluster %q produced no results, so nothing was read against it.\n",
			divergence.ReferenceCluster)
	}

	if len(divergence.Controls) == 0 {
		// An empty divergence means two different things. If some control was
		// reported on by more than one cluster, they agreed. If none was, then
		// nothing was ever compared, and saying they agreed would turn a fleet
		// nobody could measure into a clean bill of health.
		if compared.controls == 0 {
			cautils.WarningDisplay(w, "%s\n\n", nothingComparedText(compared))
			return
		}
		cautils.SuccessDisplay(w, "Every cluster agreed on every control it ran.\n\n")
		return
	}

	controls := make([]*fleet.ControlDivergence, 0, len(divergence.Controls))
	for i := range divergence.Controls {
		controls = append(controls, &divergence.Controls[i])
	}
	// Sorted on severity here rather than in the report, which stays ordered by
	// control ID so two runs stay diffable. A reader wants the worst first.
	sort.SliceStable(controls, func(i, j int) bool {
		left, right := severityRank(controls[i].Severity), severityRank(controls[j].Severity)
		if left != right {
			return left > right
		}
		return controls[i].ControlID < controls[j].ControlID
	})

	header := table.Row{"Severity", "Control", "Kind", "Passed", "Failed", "Skipped", "Not evaluated"}
	if divergence.ReferenceCluster != "" {
		header = append(header, gchalk.WithBrightWhite().Bold(divergence.ReferenceCluster))
	}

	diverging := newFleetTable(w)
	diverging.AppendHeader(header)
	for _, control := range controls {
		row := table.Row{
			getColor(severityRank(control.Severity))(control.Severity),
			fmt.Sprintf("%s %s", control.ControlID, control.Name),
			divergenceKindText(control),
			clustersText(control.Passed),
			clustersText(control.Failed),
			clustersText(control.Skipped),
			clustersText(control.NotEvaluated),
		}
		if divergence.ReferenceCluster != "" {
			row = append(row, valueOrDash(string(control.ReferenceStatus)))
		}
		diverging.AppendRow(row)
	}
	diverging.Render()
	cautils.SimpleDisplay(w, "\n")
}

// matrixComparability is how much of the matrix could actually be compared.
type matrixComparability struct {
	// clusters is how many clusters contributed anything at all.
	clusters int
	// controls is how many controls more than one cluster reported on. This is
	// the number that decides whether agreement means anything, and it is a
	// per-control count rather than a total: two clusters that scanned entirely
	// different controls contribute two clusters and no comparison.
	controls int
}

// comparability measures the matrix the divergence was computed over.
//
// It counts per control row rather than taking the union of cluster IDs across
// rows. BuildDivergence works a row at a time and drops any control fewer than
// two clusters reached an outcome on, so a fleet whose clusters scanned
// disjoint control sets produces an empty divergence while still having several
// clusters in it. Counting the union would read that as agreement.
func comparability(matrix *fleet.FleetControlMatrix) matrixComparability {
	seen := make(map[string]struct{})
	measured := matrixComparability{}

	for i := range matrix.Controls {
		byCluster := matrix.Controls[i].ByCluster
		if len(byCluster) > 1 {
			measured.controls++
		}
		for clusterID := range byCluster {
			seen[clusterID] = struct{}{}
		}
	}

	measured.clusters = len(seen)
	return measured
}

// nothingComparedText says why there was nothing to compare, which is a
// different fact depending on how much of the fleet reported at all.
func nothingComparedText(compared matrixComparability) string {
	switch compared.clusters {
	case 0:
		return "No cluster produced results, so there was nothing to compare."
	case 1:
		return "Only one cluster produced results, so there was nothing to compare."
	default:
		return "No control was reported on by more than one cluster, so there was nothing to compare."
	}
}

// newFleetTable returns a table writer in the same style the rest of the
// printers use, so the fleet summary does not arrive looking like it came from
// somewhere else.
func newFleetTable(w io.Writer) table.Writer {
	fleetTable := table.NewWriter()
	fleetTable.SetOutputMirror(w)
	fleetTable.Style().Options.SeparateHeader = true
	fleetTable.Style().Format.HeaderAlign = text.AlignLeft
	fleetTable.Style().Format.Header = text.FormatDefault
	fleetTable.Style().Box = table.StyleBoxRounded
	return fleetTable
}

// divergenceKindText says what kind of disagreement a row is, which is the
// difference between a cluster that is configured differently and one that was
// never looked at.
func divergenceKindText(control *fleet.ControlDivergence) string {
	switch {
	case control.PostureDiverges && control.CoverageGap:
		return "posture, coverage"
	case control.PostureDiverges:
		return "posture"
	case control.CoverageGap:
		return "coverage"
	default:
		return "exception"
	}
}

// exclusionText says why a cluster was held out of the fleet score, and how far
// short it fell when that reason was coverage.
//
// The floor is named alongside the coverage because the exclusion cannot be
// checked without it. "Coverage was 45%" does not tell a reader whether the
// cluster missed by a point or by half, which is the whole reason the figures
// are carried on the exclusion in the first place.
func exclusionText(excluded *fleet.ExcludedCluster, minCoverage float32) string {
	switch excluded.Reason {
	case fleet.ExcludedNotScanned:
		return "it was not scanned"
	case fleet.ExcludedNotScored:
		return "it was scanned but reported no score"
	case fleet.ExcludedLowCoverage:
		if minCoverage <= 0 {
			// Zero means no floor was set, so there is none to name and the
			// exclusion has to speak for itself.
			return fmt.Sprintf("coverage was %s, and it scored %s",
				percentOrDash(excluded.Coverage), percentOrDash(excluded.ComplianceScore))
		}
		return fmt.Sprintf("coverage was %s, below the %.0f%% floor, and it scored %s",
			percentOrDash(excluded.Coverage), minCoverage, percentOrDash(excluded.ComplianceScore))
	default:
		return string(excluded.Reason)
	}
}

// fleetStatusText colours a cluster's outcome the way the rest of Kubescape
// colours a control's, so the eye lands on the same things.
func fleetStatusText(status fleet.ClusterScanStatus) string {
	switch status {
	case fleet.ClusterScanned:
		return gchalk.WithGreen().Bold(string(status))
	case fleet.ClusterUnreachable, fleet.ClusterError:
		return gchalk.WithRed().Bold(string(status))
	case fleet.ClusterCancelled:
		return gchalk.WithYellow().Bold(string(status))
	default:
		return string(status)
	}
}

// fleetCoverageText shows a cluster's coverage, marking a degraded scan so a
// high compliance score sitting next to an incomplete one is not read as good
// news.
func fleetCoverageText(cluster *fleet.ClusterResult) string {
	if cluster.Coverage == nil {
		return notMeasured
	}
	coverage := fmt.Sprintf("%.0f%%", cluster.Coverage.CoverageScore)
	if cluster.Coverage.Degraded {
		return gchalk.WithYellow().Bold(coverage + " degraded")
	}
	return coverage
}

// clustersText joins the clusters at one outcome, or a dash when none are.
func clustersText(clusters []string) string {
	if len(clusters) == 0 {
		return notMeasured
	}
	return strings.Join(clusters, ", ")
}

// percentOrDash renders a score that may be absent. An absent score is a dash
// rather than 0%, which would read as a measurement nobody took.
func percentOrDash(score *float32) string {
	if score == nil {
		return notMeasured
	}
	return fmt.Sprintf("%.0f%%", *score)
}

// valueOrDash renders a string that may be empty.
func valueOrDash(value string) string {
	if value == "" {
		return notMeasured
	}
	return value
}
