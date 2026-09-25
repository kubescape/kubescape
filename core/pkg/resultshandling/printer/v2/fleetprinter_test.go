package printer

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/fleet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ansi matches the escape sequences gchalk emits, so assertions can be written
// against the words a reader sees rather than against colour codes that depend
// on whether the test ran attached to a terminal.
var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// renderFleet prints the report and returns the plain text of it.
func renderFleet(report *fleet.FleetReport) string {
	var out bytes.Buffer
	PrintFleetReport(&out, report)
	return ansi.ReplaceAllString(out.String(), "")
}

// scorePtr returns a pointer to v, for the fields that tell an absent
// measurement apart from a zero one.
func scorePtr(v float32) *float32 { return &v }

// matrixRow builds one control row on which each named cluster passed, so a
// test can say which clusters reported on which control.
func matrixRow(controlID string, clusterIDs ...string) fleet.FleetControlRow {
	byCluster := make(map[string]fleet.ControlStatusCell, len(clusterIDs))
	for _, clusterID := range clusterIDs {
		byCluster[clusterID] = fleet.ControlStatusCell{Status: fleet.CellPassed}
	}
	return fleet.FleetControlRow{
		ControlID: controlID, Name: "Allow privilege escalation",
		Severity: "High", ByCluster: byCluster,
	}
}

// matrixOver builds a matrix in which each named cluster reached the same
// outcome on one shared control, which is what a fleet that agrees looks like.
func matrixOver(clusterIDs ...string) fleet.FleetControlMatrix {
	return fleet.FleetControlMatrix{Controls: []fleet.FleetControlRow{
		matrixRow("C-0016", clusterIDs...),
	}}
}

// TestPrintFleetReportListsEveryCluster pins that a cluster which could not be
// scanned still gets a row. Dropping it would make the fleet look smaller and
// healthier than it is, which is the mistake the report itself exists to avoid.
func TestPrintFleetReportListsEveryCluster(t *testing.T) {
	out := renderFleet(&fleet.FleetReport{
		Clusters: []fleet.ClusterResult{
			{ClusterID: "prod", Status: fleet.ClusterScanned, ComplianceScore: scorePtr(72),
				Coverage: &cautils.ScanCoverage{CoverageScore: 88, Degraded: true}, Duration: "4m12s"},
			{ClusterID: "dr", Status: fleet.ClusterUnreachable, Error: "no route to host"},
			{ClusterID: "eu", Status: fleet.ClusterCancelled, Error: "context canceled"},
		},
	})

	for _, cluster := range []string{"prod", "dr", "eu"} {
		assert.Contains(t, out, cluster)
	}
	assert.Contains(t, out, "unreachable")
	assert.Contains(t, out, "cancelled")
	assert.Contains(t, out, "72%")
	assert.Contains(t, out, "88% degraded", "a degraded scan must say so beside its coverage")
	assert.Contains(t, out, "4m12s")
	assert.Contains(t, out, "no route to host", "the reason a cluster failed belongs in the output")
	assert.Contains(t, out, "context canceled")
}

// TestPrintFleetReportNeverPrintsZeroForAbsent covers the rule the whole
// package is built on. A cluster nobody could reach has no score, and printing
// 0% would read as fully non-compliant rather than never measured.
func TestPrintFleetReportNeverPrintsZeroForAbsent(t *testing.T) {
	out := renderFleet(&fleet.FleetReport{
		Clusters: []fleet.ClusterResult{
			{ClusterID: "dr", Status: fleet.ClusterUnreachable, Error: "no route to host"},
		},
		Compliance: fleet.ComplianceRollup{ClustersTotal: 1},
	})

	assert.NotContains(t, out, "0%", "an unmeasured cluster must not be rendered as scoring zero")
	assert.Contains(t, out, "-", "it is rendered as absent instead")
}

// TestPrintFleetReportShowsTheBasisOfTheScore pins that the fleet score never
// appears without the count of clusters behind it. A number with no basis
// printed next to it invites more confidence than it has earned.
func TestPrintFleetReportShowsTheBasisOfTheScore(t *testing.T) {
	out := renderFleet(&fleet.FleetReport{
		Clusters: []fleet.ClusterResult{{ClusterID: "prod", Status: fleet.ClusterScanned}},
		Compliance: fleet.ComplianceRollup{
			ComplianceScore: scorePtr(91), ClustersScored: 3, ClustersTotal: 30,
		},
	})

	assert.Contains(t, out, "91%")
	assert.Contains(t, out, "from 3 of 30 clusters")
}

// TestPrintFleetReportExplainsExclusions covers each reason a cluster was held
// out of the score, so the decision can be checked rather than trusted.
func TestPrintFleetReportExplainsExclusions(t *testing.T) {
	out := renderFleet(&fleet.FleetReport{
		Compliance: fleet.ComplianceRollup{
			ClustersTotal: 3,
			// A cluster is only ever held back for coverage when a floor was
			// set, so the fixture carries one.
			MinCoverage: 60,
			Excluded: []fleet.ExcludedCluster{
				{ClusterID: "dr", Reason: fleet.ExcludedNotScanned},
				{ClusterID: "eu", Reason: fleet.ExcludedNotScored},
				{ClusterID: "prod", Reason: fleet.ExcludedLowCoverage,
					Coverage: scorePtr(12), ComplianceScore: scorePtr(100)},
			},
		},
	})

	assert.Contains(t, out, "dr was not counted: it was not scanned")
	assert.Contains(t, out, "eu was not counted: it was scanned but reported no score")
	assert.Contains(t, out, "prod was not counted: coverage was 12%, below the 60% floor, and it scored 100%",
		"the uncounted score and the floor it missed both have to be visible for the exclusion to be auditable")
}

// TestPrintFleetReportOmitsTheFloorWhenThereIsNone covers a rollup carrying no
// coverage floor, where naming one would invent a threshold nobody set. Zero
// does not mean "a floor of zero", it means the run never applied one.
func TestPrintFleetReportOmitsTheFloorWhenThereIsNone(t *testing.T) {
	out := renderFleet(&fleet.FleetReport{
		Compliance: fleet.ComplianceRollup{
			ClustersTotal: 1,
			MinCoverage:   0,
			Excluded: []fleet.ExcludedCluster{
				{ClusterID: "prod", Reason: fleet.ExcludedLowCoverage,
					Coverage: scorePtr(12), ComplianceScore: scorePtr(100)},
			},
		},
	})

	assert.Contains(t, out, "prod was not counted: coverage was 12%, and it scored 100%")
	assert.NotContains(t, out, "floor", "no floor was set, so none should be named")
}

// TestPrintFleetReportMarksVacuousFrameworks pins that a framework scored in
// fewer clusters than ran it says so, since the gap is the whole signal.
func TestPrintFleetReportMarksVacuousFrameworks(t *testing.T) {
	out := renderFleet(&fleet.FleetReport{
		Compliance: fleet.ComplianceRollup{
			ClustersTotal: 2,
			Frameworks: []fleet.FrameworkRollup{
				{Name: "MITRE", ComplianceScore: scorePtr(64), ClustersScored: 1,
					ClustersReporting: 2, VacuousIn: []string{"staging"}},
				{Name: "NSA", ComplianceScore: scorePtr(86), ClustersScored: 2, ClustersReporting: 2},
			},
		},
	})

	assert.Contains(t, out, "MITRE")
	assert.Contains(t, out, "1 of 2 (1 vacuous)")
	assert.Contains(t, out, "2 of 2")
}

// TestPrintFleetReportOrdersDivergenceWorstFirst pins the sort. The report
// itself stays ordered by control ID so two runs compare equal, but a reader
// wants the row worth acting on at the top.
func TestPrintFleetReportOrdersDivergenceWorstFirst(t *testing.T) {
	out := renderFleet(&fleet.FleetReport{
		Divergence: fleet.FleetDivergence{Controls: []fleet.ControlDivergence{
			{ControlID: "C-0001", Name: "Low one", Severity: "Low", PostureDiverges: true,
				Passed: []string{"a"}, Failed: []string{"b"}},
			{ControlID: "C-0002", Name: "Critical one", Severity: "Critical", PostureDiverges: true,
				Passed: []string{"a"}, Failed: []string{"b"}},
			{ControlID: "C-0003", Name: "Medium one", Severity: "Medium", PostureDiverges: true,
				Passed: []string{"a"}, Failed: []string{"b"}},
		}},
	})

	critical, medium, low := indexOf(t, out, "Critical one"), indexOf(t, out, "Medium one"), indexOf(t, out, "Low one")
	assert.Less(t, critical, medium, "critical must come before medium")
	assert.Less(t, medium, low, "medium must come before low")
}

// TestPrintFleetReportNamesTheKindOfDisagreement pins that the two kinds are
// told apart in the output, not just in the JSON. A cluster that was never
// looked at is not a cluster that disagrees.
func TestPrintFleetReportNamesTheKindOfDisagreement(t *testing.T) {
	tests := []struct {
		name    string
		control fleet.ControlDivergence
		want    string
	}{
		{
			name:    "posture only",
			control: fleet.ControlDivergence{ControlID: "C-1", Severity: "High", PostureDiverges: true},
			want:    "posture",
		},
		{
			name:    "coverage only",
			control: fleet.ControlDivergence{ControlID: "C-2", Severity: "High", CoverageGap: true},
			want:    "coverage",
		},
		{
			name: "both at once",
			control: fleet.ControlDivergence{ControlID: "C-3", Severity: "High",
				PostureDiverges: true, CoverageGap: true},
			want: "posture, coverage",
		},
		{
			// Neither flag means the clusters differ only on whether the control
			// was applied to them, which is a decision rather than a finding.
			name:    "neither, so an exception",
			control: fleet.ControlDivergence{ControlID: "C-4", Severity: "High", Skipped: []string{"prod"}},
			want:    "exception",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := renderFleet(&fleet.FleetReport{
				Divergence: fleet.FleetDivergence{Controls: []fleet.ControlDivergence{tt.control}},
			})
			assert.Contains(t, out, tt.want)
		})
	}
}

// TestPrintFleetReportReferenceCluster covers the golden cluster column, which
// only appears when one was asked for.
func TestPrintFleetReportReferenceCluster(t *testing.T) {
	control := fleet.ControlDivergence{
		ControlID: "C-0016", Name: "Allow privilege escalation", Severity: "High",
		PostureDiverges: true, ReferenceStatus: fleet.CellFailed,
		Passed: []string{"staging"}, Failed: []string{"prod"},
	}

	withReference := renderFleet(&fleet.FleetReport{
		Divergence: fleet.FleetDivergence{
			ReferenceCluster: "prod", Controls: []fleet.ControlDivergence{control},
		},
	})
	assert.Contains(t, withReference, "failed", "the reference's own verdict is the point of naming one")

	control.ReferenceStatus = ""
	withoutReference := renderFleet(&fleet.FleetReport{
		Divergence: fleet.FleetDivergence{Controls: []fleet.ControlDivergence{control}},
	})
	assert.NotContains(t, withoutReference, "Not evaluated │ prod",
		"no reference was asked for, so no reference column")
}

// TestPrintFleetReportReferenceUnavailable pins that a reference which produced
// nothing is called out. Printing the rows without a word about it would leave
// the reader believing they compared against a cluster that was never there.
func TestPrintFleetReportReferenceUnavailable(t *testing.T) {
	out := renderFleet(&fleet.FleetReport{
		Divergence: fleet.FleetDivergence{
			ReferenceCluster: "golden", ReferenceUnavailable: true,
			Controls: []fleet.ControlDivergence{
				{ControlID: "C-1", Severity: "High", PostureDiverges: true,
					Passed: []string{"a"}, Failed: []string{"b"}},
			},
		},
	})

	assert.Contains(t, out, "golden")
	assert.Contains(t, out, "produced no results")
}

// TestPrintFleetReportAgreementIsWorthSaying pins that a fleet which agrees
// everywhere gets told so, rather than an empty space a reader has to interpret.
//
// It takes two clusters that both reported, because that is the only situation
// in which agreement means anything. With fewer, nothing was compared.
func TestPrintFleetReportAgreementIsWorthSaying(t *testing.T) {
	out := renderFleet(&fleet.FleetReport{
		Clusters: []fleet.ClusterResult{
			{ClusterID: "prod", Status: fleet.ClusterScanned},
			{ClusterID: "staging", Status: fleet.ClusterScanned},
		},
		Compliance:    fleet.ComplianceRollup{ComplianceScore: scorePtr(100), ClustersScored: 2, ClustersTotal: 2},
		ControlMatrix: matrixOver("prod", "staging"),
	})

	assert.Contains(t, out, "Every cluster agreed on every control it ran")
}

// TestPrintFleetReportWillNotClaimAgreementNobodyReached covers the fleet that
// produced too little to compare.
//
// BuildDivergence drops any control fewer than two clusters reached an outcome
// on, so a run where every context failed, or where one succeeded and the rest
// did not, arrives here with an empty divergence that looks exactly like
// agreement. Reporting it as agreement would turn the worst runs into the
// cleanest-looking summaries.
func TestPrintFleetReportWillNotClaimAgreementNobodyReached(t *testing.T) {
	t.Run("every context unreachable", func(t *testing.T) {
		out := renderFleet(&fleet.FleetReport{
			Clusters: []fleet.ClusterResult{
				{ClusterID: "prod", Status: fleet.ClusterUnreachable, Error: "i/o timeout"},
				{ClusterID: "dr", Status: fleet.ClusterUnreachable, Error: "i/o timeout"},
			},
		})

		assert.Contains(t, out, "No cluster produced results, so there was nothing to compare")
		assert.NotContains(t, out, "agreed", "nobody reported, so nobody agreed")
	})

	t.Run("one scanned and the rest failed", func(t *testing.T) {
		out := renderFleet(&fleet.FleetReport{
			Clusters: []fleet.ClusterResult{
				{ClusterID: "prod", Status: fleet.ClusterScanned},
				{ClusterID: "dr", Status: fleet.ClusterUnreachable, Error: "i/o timeout"},
			},
			ControlMatrix: matrixOver("prod"),
		})

		assert.Contains(t, out, "Only one cluster produced results, so there was nothing to compare")
		assert.NotContains(t, out, "agreed", "one cluster has nobody to agree with")
	})
}

// TestPrintFleetReportWillNotClaimAgreementAcrossDisjointControls covers two
// clusters that both reported, but never on the same control.
//
// The divergence comes out of BuildDivergence rather than being written by
// hand, because the point is the interaction between the two: BuildDivergence
// works a control at a time and drops any row fewer than two clusters reached
// an outcome on, so disjoint control sets produce an empty divergence out of a
// fleet that plainly has two clusters in it. Counting clusters across the whole
// matrix reads that as agreement, which is the bug this pins.
func TestPrintFleetReportWillNotClaimAgreementAcrossDisjointControls(t *testing.T) {
	matrix := fleet.FleetControlMatrix{Controls: []fleet.FleetControlRow{
		matrixRow("C-0016", "prod"),
		matrixRow("C-0038", "staging"),
	}}

	out := renderFleet(&fleet.FleetReport{
		Clusters: []fleet.ClusterResult{
			{ClusterID: "prod", Status: fleet.ClusterScanned},
			{ClusterID: "staging", Status: fleet.ClusterScanned},
		},
		ControlMatrix: matrix,
		Divergence:    fleet.BuildDivergence(matrix, ""),
	})

	assert.Contains(t, out, "No control was reported on by more than one cluster")
	assert.NotContains(t, out, "agreed",
		"the clusters scanned different controls, so they never agreed on anything")
}

// TestPrintFleetReportStillReportsAgreementOnASharedControl is the other half
// of the case above: once the clusters do share a control, agreement is a real
// finding and has to survive the guard that suppresses the vacuous one.
func TestPrintFleetReportStillReportsAgreementOnASharedControl(t *testing.T) {
	matrix := fleet.FleetControlMatrix{Controls: []fleet.FleetControlRow{
		matrixRow("C-0016", "prod", "staging"),
		matrixRow("C-0038", "staging"),
	}}

	out := renderFleet(&fleet.FleetReport{
		Clusters: []fleet.ClusterResult{
			{ClusterID: "prod", Status: fleet.ClusterScanned},
			{ClusterID: "staging", Status: fleet.ClusterScanned},
		},
		ControlMatrix: matrix,
		Divergence:    fleet.BuildDivergence(matrix, ""),
	})

	assert.Contains(t, out, "Every cluster agreed on every control it ran",
		"they shared C-0016 and agreed on it, which is worth saying")
}

// TestPrintFleetReportHandlesNothing covers the degenerate inputs, since a
// summary that panics on an empty fleet would take down a run that had
// otherwise succeeded.
func TestPrintFleetReportHandlesNothing(t *testing.T) {
	assert.NotPanics(t, func() { PrintFleetReport(&bytes.Buffer{}, nil) })

	var out bytes.Buffer
	PrintFleetReport(&out, nil)
	assert.Empty(t, out.String(), "a nil report has nothing to say")

	empty := renderFleet(&fleet.FleetReport{})
	assert.Contains(t, empty, "No clusters were scanned")
}

// indexOf returns where needle appears in out, failing the test when it is
// absent so an ordering assertion cannot silently compare two -1s.
func indexOf(t *testing.T, out, needle string) int {
	t.Helper()
	i := strings.Index(out, needle)
	require.GreaterOrEqual(t, i, 0, "expected %q in the output", needle)
	return i
}

// TestPrintFleetReportDoesNotReorderTheReport pins that printing is a read. The
// summary sorts by severity for the reader, but the report itself stays ordered
// by control ID so two runs of an unchanged fleet still compare equal, and a
// caller writing the JSON afterwards must get what it built.
func TestPrintFleetReportDoesNotReorderTheReport(t *testing.T) {
	report := &fleet.FleetReport{
		Divergence: fleet.FleetDivergence{Controls: []fleet.ControlDivergence{
			{ControlID: "C-0001", Severity: "Low", PostureDiverges: true,
				Passed: []string{"a"}, Failed: []string{"b"}},
			{ControlID: "C-0002", Severity: "Critical", PostureDiverges: true,
				Passed: []string{"a"}, Failed: []string{"b"}},
		}},
	}

	PrintFleetReport(&bytes.Buffer{}, report)

	assert.Equal(t, "C-0001", report.Divergence.Controls[0].ControlID,
		"printing must not reorder the report it was given")
	assert.Equal(t, "C-0002", report.Divergence.Controls[1].ControlID)
}

// TestPrintFleetReportSurvivesUnknownValues covers values the printer has no
// case for, which is what a report written by a newer Kubescape would carry. It
// has to render something rather than drop the row or panic, because a summary
// that dies takes down a run that had otherwise succeeded.
func TestPrintFleetReportSurvivesUnknownValues(t *testing.T) {
	out := renderFleet(&fleet.FleetReport{
		Clusters: []fleet.ClusterResult{
			{ClusterID: "odd", Status: fleet.ClusterScanStatus("something-new")},
		},
		Compliance: fleet.ComplianceRollup{
			ClustersTotal: 1,
			Excluded: []fleet.ExcludedCluster{
				{ClusterID: "odd", Reason: fleet.ExclusionReason("a-new-reason")},
			},
		},
		Divergence: fleet.FleetDivergence{Controls: []fleet.ControlDivergence{
			{ControlID: "C-1", Severity: "", PostureDiverges: true,
				Passed: []string{"a"}, Failed: []string{"b"}},
		}},
	})

	assert.Contains(t, out, "something-new", "an unrecognised status is still shown")
	assert.Contains(t, out, "a-new-reason", "an unrecognised reason is still shown")
	assert.Contains(t, out, "C-1", "a control with no severity is still listed")
}

// TestPrintFleetReportReportsAnUnavailableReferenceWithNoDivergence covers the
// run where the reference cluster produced nothing and the clusters that did
// report happened to agree on everything.
//
// The agreement case returns early, so it used to swallow the warning in
// exactly the run where it is hardest to notice: the summary read as a clean
// bill of health while the cluster the operator asked everything to be measured
// against had never been read at all.
func TestPrintFleetReportReportsAnUnavailableReferenceWithNoDivergence(t *testing.T) {
	out := renderFleet(&fleet.FleetReport{
		Clusters: []fleet.ClusterResult{
			{ClusterID: "prod", Status: fleet.ClusterScanned},
			{ClusterID: "dr", Status: fleet.ClusterUnreachable, Error: "dial tcp: timeout"},
		},
		Divergence: fleet.FleetDivergence{
			ReferenceCluster:     "dr",
			ReferenceUnavailable: true,
		},
	})

	assert.Contains(t, out, "dr", "the reference has to be named")
	assert.Contains(t, out, "produced no results",
		"a reference nobody could read is worth saying even when nothing diverged")
	assert.NotContains(t, out, "agreed",
		"only prod reported, so there was nobody for it to agree with")
}
