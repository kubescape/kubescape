package fleet

import (
	"encoding/json"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// goldenPath is the fixture TestFleetReportGoldenFile compares against.
const goldenPath = "testdata/fleetreport_golden.json"

// updateGolden regenerates testdata/fleetreport_golden.json instead of
// comparing against it. Deliberate changes to the JSON envelope are made by
// running the test with it and reviewing the resulting diff.
var updateGolden = flag.Bool("update-golden", false, "regenerate the fleet report golden fixture under testdata/")

// newFleetReport builds the report the wire-format tests work from.
//
// Clusters and ControlMatrix are derived from one slice of results rather than
// assembled independently. That is the point of the helper: a matrix cell for a
// cluster missing from Clusters, or a cluster marked scanned with no report
// behind it, is not a report a consumer should ever have to accept, so the
// fixtures must not be able to describe one. Building both views from the same
// input makes that impossible by construction rather than by review.
func newFleetReport() FleetReport {
	results := []ClusterResult{
		scannedCluster("prod", failed("C-0016", "Allow privilege escalation", 18)),
		scannedCluster("staging", passed("C-0016", "Allow privilege escalation")),
		unreachableCluster("dr", "context deadline exceeded"),
	}

	// Vary the measurements so the fixture pins a degraded scan and a healthy
	// one side by side, rather than two identical rows.
	results[0].ComplianceScore = score(72)
	results[0].Coverage = &cautils.ScanCoverage{
		CoverageScore:     88,
		EvaluatedControls: 44,
		TotalControls:     50,
		Degraded:          true,
	}
	results[0].Duration = "4m12s"
	results[1].Duration = "2m05s"

	return FleetReport{
		Metadata: FleetMetadata{
			GeneratedAt:      time.Date(2026, 8, 14, 9, 30, 0, 0, time.UTC),
			KubescapeVersion: "v4.0.0",
			Contexts:         []string{"prod", "staging", "dr"},
		},
		Clusters:      results,
		ControlMatrix: BuildControlMatrix(results),
	}
}

// requireFleetReportIsSelfConsistent fails unless the report obeys the
// invariants the types declare, so a fixture cannot bless output that a
// consumer would have to treat as incomplete.
//
// Three things have to hold. A cluster marked scanned carries a report, because
// Scanned() promises exactly that and everything downstream dereferences on the
// strength of it. Every matrix cell names a cluster that appears in Clusters and
// was actually scanned, because a verdict attributed to a cluster the report
// does not otherwise mention cannot be traced back to anything. And every
// cluster's context appears in Metadata.Contexts, which is what lets a consumer
// tell a context that produced no entry from one that was never requested.
func requireFleetReportIsSelfConsistent(t *testing.T, report *FleetReport) {
	t.Helper()

	byID := make(map[string]*ClusterResult, len(report.Clusters))
	for i := range report.Clusters {
		cluster := &report.Clusters[i]
		byID[cluster.ClusterID] = cluster

		if cluster.Status == ClusterScanned {
			assert.NotNil(t, cluster.Report,
				"cluster %q is marked scanned but carries no report", cluster.ClusterID)
		}
		assert.Contains(t, report.Metadata.Contexts, cluster.Context,
			"cluster %q was reported but its context is not in metadata.contexts", cluster.ClusterID)
	}

	for _, row := range report.ControlMatrix.Controls {
		for clusterID := range row.ByCluster {
			cluster, ok := byID[clusterID]
			if !assert.True(t, ok,
				"control %s has a cell for %q, which is absent from clusters", row.ControlID, clusterID) {
				continue
			}
			assert.True(t, cluster.Scanned(),
				"control %s has a cell for %q, which produced no usable report", row.ControlID, clusterID)
		}
	}
}

// TestFleetReportGoldenFile pins the serialised shape of the report.
//
// The JSON is what a CI job or a dashboard consumes, so a field renamed or
// dropped by accident breaks consumers rather than the compiler. Comparing
// against a golden fixture makes any change to the envelope show up as a diff
// at review time. A fixed GeneratedAt keeps the output deterministic; run with
// `go test -update-golden` to regenerate the fixture.
func TestFleetReportGoldenFile(t *testing.T) {
	report := newFleetReport()
	requireFleetReportIsSelfConsistent(t, &report)

	got, err := json.MarshalIndent(report, "", "  ")
	require.NoError(t, err)
	got = append(got, '\n')

	if *updateGolden {
		require.NoError(t, os.WriteFile(goldenPath, got, 0o600))
	}

	want, err := os.ReadFile(goldenPath)
	require.NoError(t, err, "golden fixture missing, run `go test -update-golden`")
	assert.Equal(t, string(want), string(got), "fleet report JSON diverged from testdata/fleetreport_golden.json")
}

// TestClusterResultOmitsUnmeasuredFields checks that a cluster which was never
// scanned serialises without the fields it has no value for, rather than with
// zeroes. A fabricated "0% compliant, 0% covered" row sitting next to real
// measurements is worse than an absent one, because it reads as a finding.
func TestClusterResultOmitsUnmeasuredFields(t *testing.T) {
	raw, err := json.Marshal(unreachableCluster("dr", "no route to host"))
	require.NoError(t, err)

	var decoded map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &decoded))

	for _, key := range []string{"report", "complianceScore", "coverage"} {
		assert.NotContains(t, decoded, key, "an unscanned cluster must not carry a %q key", key)
	}
	assert.Contains(t, decoded, "status", "every cluster must carry a status")
	assert.Contains(t, decoded, "error", "an unscanned cluster must carry the error that produced its status")
}

// TestFleetReportRoundTrips checks that the report survives a marshal and
// unmarshal unchanged. The struct tags are the wire contract, so a tag that
// does not match its field would let a report serialise and come back with the
// value silently missing.
func TestFleetReportRoundTrips(t *testing.T) {
	want := newFleetReport()
	requireFleetReportIsSelfConsistent(t, &want)

	raw, err := json.Marshal(want)
	require.NoError(t, err)

	var got FleetReport
	require.NoError(t, json.Unmarshal(raw, &got))

	// The decoded report has to satisfy the same invariants as the encoded one.
	// A tag mismatch that dropped Clusters or ByCluster would otherwise show up
	// only as a nil map somewhere downstream.
	requireFleetReportIsSelfConsistent(t, &got)

	assert.True(t, got.Metadata.GeneratedAt.Equal(want.Metadata.GeneratedAt))
	assert.Equal(t, want.Metadata.Contexts, got.Metadata.Contexts)

	require.Len(t, got.Clusters, len(want.Clusters))
	assert.Equal(t, ClusterScanned, got.Clusters[0].Status)
	require.NotNil(t, got.Clusters[0].ComplianceScore)
	assert.InDelta(t, 72, *got.Clusters[0].ComplianceScore, 0)
	require.NotNil(t, got.Clusters[0].Coverage)
	assert.True(t, got.Clusters[0].Coverage.Degraded)
	assert.Equal(t, ClusterUnreachable, got.Clusters[2].Status)
	assert.Equal(t, "context deadline exceeded", got.Clusters[2].Error)
	assert.Nil(t, got.Clusters[2].ComplianceScore, "an unscanned cluster must not decode a score")

	require.Len(t, got.ControlMatrix.Controls, 1)
	row := got.ControlMatrix.Controls[0]
	assert.Equal(t, "C-0016", row.ControlID)
	assert.Equal(t, CellFailed, row.ByCluster["prod"].Status)
	assert.Equal(t, CellPassed, row.ByCluster["staging"].Status)
	assert.NotContains(t, row.ByCluster, "dr", "an unreachable cluster must not decode a cell")
}

// TestClusterResultScanned pins the guard the aggregation dereferences behind.
// The case that matters is the second one: a result claiming ClusterScanned
// with no report is missing data, not usable data, and treating the status
// alone as sufficient would panic on the next field access.
func TestClusterResultScanned(t *testing.T) {
	tests := []struct {
		name   string
		result ClusterResult
		want   bool
	}{
		{
			name:   "scanned with a report",
			result: scannedCluster("prod", passed("C-0016", "Allow privilege escalation")),
			want:   true,
		},
		{
			name:   "scanned status but no report is not usable data",
			result: ClusterResult{ClusterID: "prod", Status: ClusterScanned},
			want:   false,
		},
		{
			name:   "unreachable",
			result: unreachableCluster("dr", "no route to host"),
			want:   false,
		},
		{
			name:   "errored",
			result: ClusterResult{ClusterID: "dr", Status: ClusterError, Error: "policy download failed"},
			want:   false,
		},
		{
			name:   "cancelled before it ran",
			result: ClusterResult{ClusterID: "dr", Status: ClusterCancelled, Error: "context canceled"},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.result.Scanned())
		})
	}
}

// TestClusterResultScored covers the stricter guard used by anything that
// averages across clusters. A scanned cluster can still be missing its score or
// its coverage, and folding either absence in as a zero would report a fleet as
// less compliant than it was measured to be.
func TestClusterResultScored(t *testing.T) {
	scanned := scannedCluster("prod", passed("C-0016", "Allow privilege escalation"))

	noScore := scannedCluster("staging", passed("C-0016", "Allow privilege escalation"))
	noScore.ComplianceScore = nil

	noCoverage := scannedCluster("dr", passed("C-0016", "Allow privilege escalation"))
	noCoverage.Coverage = nil

	tests := []struct {
		name   string
		result ClusterResult
		want   bool
	}{
		{name: "scanned with both measurements", result: scanned, want: true},
		{name: "scanned but never scored", result: noScore, want: false},
		{name: "scanned but no coverage recorded", result: noCoverage, want: false},
		{name: "unreachable", result: unreachableCluster("dr", "no route to host"), want: false},
		{
			name:   "cancelled before it ran",
			result: ClusterResult{ClusterID: "dr", Status: ClusterCancelled},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.result.Scored())
		})
	}
}
