package fleet

import (
	"testing"

	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildControlMatrix covers what a row is made of and, more importantly,
// which clusters are allowed to put a cell in one. A cluster that produced no
// usable report contributes nothing, so a cluster nobody could reach cannot
// improve or worsen the fleet's apparent posture.
func TestBuildControlMatrix(t *testing.T) {
	tests := []struct {
		name     string
		results  []ClusterResult
		wantRows []string
		assert   func(t *testing.T, matrix FleetControlMatrix)
	}{
		{
			name: "control present in every cluster gets a cell per cluster",
			results: []ClusterResult{
				scannedCluster("prod", failed("C-0016", "Allow privilege escalation", 4)),
				scannedCluster("staging", passed("C-0016", "Allow privilege escalation")),
			},
			wantRows: []string{"C-0016"},
			assert: func(t *testing.T, matrix FleetControlMatrix) {
				t.Helper()

				row := matrix.Controls[0]
				require.Len(t, row.ByCluster, 2)
				requireCell(t, row, "prod", CellFailed)
				requireCell(t, row, "staging", CellPassed)

				assert.Equal(t, 4, row.ByCluster["prod"].FailedResources)
				assert.Equal(t, "Allow privilege escalation", row.Name)
				assert.Equal(t, apis.SeverityHighString, row.Severity)
			},
		},
		{
			name: "control missing from one cluster leaves that cluster out of the row",
			results: []ClusterResult{
				scannedCluster("prod",
					failed("C-0016", "Allow privilege escalation", 1),
					passed("C-0038", "Host PID/IPC privileges"),
				),
				scannedCluster("staging", passed("C-0016", "Allow privilege escalation")),
			},
			wantRows: []string{"C-0016", "C-0038"},
			assert: func(t *testing.T, matrix FleetControlMatrix) {
				t.Helper()

				hostPID := matrix.Controls[1]
				assert.NotContains(t, hostPID.ByCluster, "staging",
					"staging did not run C-0038, so it should have no cell in that row")
				requireCell(t, hostPID, "prod", CellPassed)
			},
		},
		{
			name: "a control that could not be evaluated is not reported as skipped",
			results: []ClusterResult{
				scannedCluster("prod", notEvaluated("C-0260", "Missing network policy")),
				scannedCluster("staging", skipped("C-0260", "Missing network policy")),
			},
			wantRows: []string{"C-0260"},
			assert: func(t *testing.T, matrix FleetControlMatrix) {
				t.Helper()

				// Both clusters record the control as apis.StatusSkipped and only
				// the sub-status tells them apart. Collapsing them here would hide
				// a coverage gap behind an apparent agreement.
				requireCell(t, matrix.Controls[0], "prod", CellNotEvaluated)
				requireCell(t, matrix.Controls[0], "staging", CellSkipped)
			},
		},
		{
			name: "unreachable clusters contribute no cells",
			results: []ClusterResult{
				scannedCluster("prod", failed("C-0016", "Allow privilege escalation", 2)),
				unreachableCluster("dr", "context deadline exceeded"),
			},
			wantRows: []string{"C-0016"},
			assert: func(t *testing.T, matrix FleetControlMatrix) {
				t.Helper()

				row := matrix.Controls[0]
				assert.NotContains(t, row.ByCluster, "dr",
					"dr was never scanned, so it must not appear as a cell")
				assert.Len(t, row.ByCluster, 1)
			},
		},
		{
			name: "a scanned status with a nil report is skipped rather than dereferenced",
			results: []ClusterResult{
				{ClusterID: "prod", Context: "prod", Status: ClusterScanned},
				scannedCluster("staging", passed("C-0016", "Allow privilege escalation")),
			},
			wantRows: []string{"C-0016"},
			assert: func(t *testing.T, matrix FleetControlMatrix) {
				t.Helper()

				assert.NotContains(t, matrix.Controls[0].ByCluster, "prod",
					"a cluster with no report must not produce a cell")
			},
		},
		{
			name: "every cluster failing yields an empty matrix, not a panic",
			results: []ClusterResult{
				unreachableCluster("prod", "no route to host"),
				{ClusterID: "dr", Context: "dr", Status: ClusterError, Error: "policy download failed"},
				{ClusterID: "eu", Context: "eu", Status: ClusterCancelled, Error: "context canceled"},
			},
			wantRows: []string{},
		},
		{
			name: "a cancelled cluster contributes no cells",
			results: []ClusterResult{
				scannedCluster("prod", failed("C-0016", "Allow privilege escalation", 2)),
				{ClusterID: "dr", Context: "dr", Status: ClusterCancelled, Error: "context canceled"},
			},
			wantRows: []string{"C-0016"},
			assert: func(t *testing.T, matrix FleetControlMatrix) {
				t.Helper()

				// An interrupted run learned nothing about dr. Giving it a cell
				// would put a verdict in the matrix that was never measured.
				assert.NotContains(t, matrix.Controls[0].ByCluster, "dr")
				assert.Len(t, matrix.Controls[0].ByCluster, 1)
			},
		},
		{
			name:     "no clusters at all yields an empty matrix",
			results:  nil,
			wantRows: []string{},
		},
		{
			name: "a single cluster still produces a full matrix",
			results: []ClusterResult{
				scannedCluster("prod",
					passed("C-0038", "Host PID/IPC privileges"),
					failed("C-0016", "Allow privilege escalation", 3),
				),
			},
			wantRows: []string{"C-0016", "C-0038"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matrix := BuildControlMatrix(tt.results)

			got := make([]string, 0, len(matrix.Controls))
			for _, row := range matrix.Controls {
				got = append(got, row.ControlID)
			}
			require.Equal(t, tt.wantRows, got)

			if tt.assert != nil {
				tt.assert(t, matrix)
			}
		})
	}
}

// TestCellStatusCoversEveryScanningStatus pins how each upstream status maps
// into a cell, including the ones no fixture produces today.
//
// The cases that matter are the last two. A control whose status was never set,
// and the deprecated "error" status, both reach no verdict, so reporting either
// as skipped would claim a deliberate exclusion nobody made and would compare
// equal to a real skip on another cluster. They map to notEvaluated so the gap
// stays visible. The deprecated "excluded" and "irrelevant" spellings are
// genuine non-application and stay skipped.
func TestCellStatusCoversEveryScanningStatus(t *testing.T) {
	tests := []struct {
		name   string
		status apis.ScanningStatus
		sub    apis.ScanningSubStatus
		want   CellStatus
	}{
		{"passed", apis.StatusPassed, "", CellPassed},
		{"failed", apis.StatusFailed, "", CellFailed},
		{"skipped as irrelevant", apis.StatusSkipped, apis.SubStatusIrrelevant, CellSkipped},
		{"skipped with no sub-status", apis.StatusSkipped, "", CellSkipped},
		{"skipped because it could not be evaluated", apis.StatusSkipped, apis.SubStatusNotEvaluated, CellNotEvaluated},
		{"status never set", apis.StatusUnknown, "", CellNotEvaluated},
		{"deprecated error status", apis.StatusError, "", CellNotEvaluated},
		{"deprecated excluded status", apis.StatusExcluded, "", CellSkipped},
		{"deprecated irrelevant status", apis.StatusIrrelevant, "", CellSkipped},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := controlSpec{
				id: "C-0016", name: "Allow privilege escalation",
				status: tt.status, subStatus: tt.sub, scoreFactor: 8,
			}
			matrix := BuildControlMatrix([]ClusterResult{scannedCluster("prod", spec)})

			require.Len(t, matrix.Controls, 1)
			assert.Equal(t, tt.want, matrix.Controls[0].ByCluster["prod"].Status)
		})
	}
}

// TestBuildControlMatrixReadsLegacyStatusWithoutMutatingTheReport covers a
// report written before StatusInfo existed, where the verdict lives only in the
// deprecated top-level Status field.
//
// Two things have to hold at once. The legacy field still has to produce a
// verdict, because ControlSummary.GetStatus backfills StatusInfo from it. And
// that backfill is a write: it modifies the summary it is called on. Building a
// matrix is a read of the fleet's results, so it must not leave the reports it
// read from in a different state than it found them, or a caller that prints a
// report after aggregating it would be printing something the aggregation
// edited. newControlStatusCell takes the loop's copy for exactly this reason,
// and this pins it.
func TestBuildControlMatrixReadsLegacyStatusWithoutMutatingTheReport(t *testing.T) {
	cluster := scannedCluster("prod", legacyStatus("C-0016", "Allow privilege escalation", apis.StatusFailed))

	before := cluster.Report.SummaryDetails.Controls["C-0016"]
	require.Equal(t, apis.StatusUnknown, before.StatusInfo.Status(),
		"fixture must start with an empty StatusInfo for this test to mean anything")

	matrix := BuildControlMatrix([]ClusterResult{cluster})

	require.Len(t, matrix.Controls, 1)
	assert.Equal(t, CellFailed, matrix.Controls[0].ByCluster["prod"].Status,
		"a control whose verdict is only in the legacy Status field must still reach a cell")

	after := cluster.Report.SummaryDetails.Controls["C-0016"]
	assert.Equal(t, apis.StatusUnknown, after.StatusInfo.Status(),
		"BuildControlMatrix backfilled StatusInfo on the source report: reading the matrix must leave "+
			"the reports it was built from byte for byte as they arrived")
}

// TestBuildControlMatrixOrderIsIndependentOfInput guards the sort in
// BuildControlMatrix. Control summaries live in a map, so without it the rows
// would follow Go's randomised map iteration and two reports of an unchanged
// fleet would not compare equal.
func TestBuildControlMatrixOrderIsIndependentOfInput(t *testing.T) {
	specs := []controlSpec{
		passed("C-0038", "Host PID/IPC privileges"),
		failed("C-0016", "Allow privilege escalation", 1),
		skipped("C-0260", "Missing network policy"),
		passed("C-0017", "Immutable container filesystem"),
	}
	want := []string{"C-0016", "C-0017", "C-0038", "C-0260"}

	// Repeat so a run that happened to hash in the right order cannot pass by
	// luck.
	for i := 0; i < 20; i++ {
		matrix := BuildControlMatrix([]ClusterResult{scannedCluster("prod", specs...)})

		got := make([]string, 0, len(matrix.Controls))
		for _, row := range matrix.Controls {
			got = append(got, row.ControlID)
		}
		require.Equal(t, want, got, "row order changed on iteration %d", i)
	}
}

// TestBuildControlMatrixReadsComplianceScore covers the distinction between a
// control that scored zero and one that was never scored: ControlSummary
// reports an absent compliance score as -1, and the cell has to carry that
// through rather than flattening it to 0.
func TestBuildControlMatrixReadsComplianceScore(t *testing.T) {
	matrix := BuildControlMatrix([]ClusterResult{
		scannedCluster("prod", failed("C-0016", "Allow privilege escalation", 2)),
		scannedCluster("staging", notEvaluated("C-0016", "Allow privilege escalation")),
	})

	require.Len(t, matrix.Controls, 1)
	row := matrix.Controls[0]

	// A delta of zero is exact equality. Both values are sentinels copied
	// through verbatim rather than computed, so anything looser would stop the
	// test from telling -1 and 0 apart, which is the whole point of it.
	assert.InDelta(t, 0, row.ByCluster["prod"].ComplianceScore, 0,
		"a control that scored zero must be reported as zero")
	assert.InDelta(t, -1, row.ByCluster["staging"].ComplianceScore, 0,
		"an unscored control must not be reported as scoring zero")
}
