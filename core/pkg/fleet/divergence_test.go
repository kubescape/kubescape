package fleet

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// divergenceFor builds a matrix from the clusters and returns the divergence,
// so a test can describe the fleet it means rather than a matrix literal.
func divergenceFor(reference string, clusters ...ClusterResult) FleetDivergence {
	return BuildDivergence(BuildControlMatrix(clusters), reference)
}

// controlByID finds one control in a divergence, failing the test when it is
// absent.
func controlByID(t *testing.T, divergence FleetDivergence, controlID string) ControlDivergence {
	t.Helper()
	for i := range divergence.Controls {
		if divergence.Controls[i].ControlID == controlID {
			return divergence.Controls[i]
		}
	}
	t.Fatalf("control %s is not reported as diverging", controlID)
	return ControlDivergence{}
}

// TestBuildDivergenceReportsOnlyDisagreement pins which controls reach the
// report at all. A fleet that agrees produces nothing, because a list of every
// control every cluster got right is the grid again rather than an answer.
func TestBuildDivergenceReportsOnlyDisagreement(t *testing.T) {
	tests := []struct {
		name     string
		clusters []ClusterResult
		wantRows []string
	}{
		{
			name: "a fleet that agrees everywhere has nothing to report",
			clusters: []ClusterResult{
				scannedCluster("prod", failed("C-0016", "Allow privilege escalation", 2)),
				scannedCluster("staging", failed("C-0016", "Allow privilege escalation", 5)),
			},
			wantRows: nil,
		},
		{
			name: "one cluster passing what another fails is reported",
			clusters: []ClusterResult{
				scannedCluster("prod", failed("C-0016", "Allow privilege escalation", 2)),
				scannedCluster("staging", passed("C-0016", "Allow privilege escalation")),
			},
			wantRows: []string{"C-0016"},
		},
		{
			// A fleet that uniformly failed to measure something has a coverage
			// problem, not a disagreement, and the matrix already shows it.
			name: "a control nobody could evaluate is not a disagreement",
			clusters: []ClusterResult{
				scannedCluster("prod", notEvaluated("C-0260", "Missing network policy")),
				scannedCluster("staging", notEvaluated("C-0260", "Missing network policy")),
			},
			wantRows: nil,
		},
		{
			name: "only the controls that differ are reported",
			clusters: []ClusterResult{
				scannedCluster("prod",
					failed("C-0016", "Allow privilege escalation", 2),
					passed("C-0038", "Host PID/IPC privileges"),
				),
				scannedCluster("staging",
					passed("C-0016", "Allow privilege escalation"),
					passed("C-0038", "Host PID/IPC privileges"),
				),
			},
			wantRows: []string{"C-0016"},
		},
		{
			name: "a control only one cluster ran is not a disagreement",
			clusters: []ClusterResult{
				scannedCluster("prod", failed("C-0016", "Allow privilege escalation", 2)),
				scannedCluster("staging", passed("C-0038", "Host PID/IPC privileges")),
			},
			wantRows: nil,
		},
		{
			name: "a cluster that could not be scanned cannot disagree",
			clusters: []ClusterResult{
				scannedCluster("prod", failed("C-0016", "Allow privilege escalation", 2)),
				unreachableCluster("dr", "no route to host"),
			},
			wantRows: nil,
		},
		{
			name:     "no clusters at all",
			clusters: nil,
			wantRows: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			divergence := divergenceFor("", tt.clusters...)

			got := make([]string, 0, len(divergence.Controls))
			for _, control := range divergence.Controls {
				got = append(got, control.ControlID)
			}
			if len(tt.wantRows) == 0 {
				assert.Empty(t, got)
				return
			}
			assert.Equal(t, tt.wantRows, got)
		})
	}
}

// TestBuildDivergenceSeparatesPostureFromCoverage is the point of the whole
// type. A cluster failing what another passes is a real difference. A cluster
// that could not evaluate the control says nothing about posture either way,
// and reporting the two the same would send somebody chasing a difference that
// does not exist.
func TestBuildDivergenceSeparatesPostureFromCoverage(t *testing.T) {
	tests := []struct {
		name        string
		clusters    []ClusterResult
		wantPosture bool
		wantGap     bool
		assert      func(t *testing.T, control ControlDivergence)
	}{
		{
			name: "passed against failed is a difference in posture",
			clusters: []ClusterResult{
				scannedCluster("prod", failed("C-0016", "Allow privilege escalation", 2)),
				scannedCluster("staging", passed("C-0016", "Allow privilege escalation")),
			},
			wantPosture: true,
			wantGap:     false,
			assert: func(t *testing.T, control ControlDivergence) {
				t.Helper()
				assert.Equal(t, []string{"staging"}, control.Passed)
				assert.Equal(t, []string{"prod"}, control.Failed)
			},
		},
		{
			name: "a verdict against a control that could not run is a coverage gap",
			clusters: []ClusterResult{
				scannedCluster("prod", passed("C-0016", "Allow privilege escalation")),
				scannedCluster("staging", notEvaluated("C-0016", "Allow privilege escalation")),
			},
			wantPosture: false,
			wantGap:     true,
			assert: func(t *testing.T, control ControlDivergence) {
				t.Helper()
				assert.Equal(t, []string{"staging"}, control.NotEvaluated,
					"staging not looking says nothing about whether it would have passed")
			},
		},
		{
			name: "a fleet can have both at once",
			clusters: []ClusterResult{
				scannedCluster("prod", failed("C-0016", "Allow privilege escalation", 2)),
				scannedCluster("staging", passed("C-0016", "Allow privilege escalation")),
				scannedCluster("dr", notEvaluated("C-0016", "Allow privilege escalation")),
			},
			wantPosture: true,
			wantGap:     true,
		},
		{
			// Neither flag, because an exception is a decision about whether the
			// control applies rather than a finding about the cluster.
			name: "an exception on one cluster is neither",
			clusters: []ClusterResult{
				scannedCluster("prod", passed("C-0016", "Allow privilege escalation")),
				scannedCluster("staging", skipped("C-0016", "Allow privilege escalation")),
			},
			wantPosture: false,
			wantGap:     false,
			assert: func(t *testing.T, control ControlDivergence) {
				t.Helper()
				assert.Equal(t, []string{"staging"}, control.Skipped)
			},
		},
		{
			// The pair the matrix exists to keep apart, one level up. Both
			// clusters record apis.StatusSkipped and only the sub-status tells
			// them apart, so collapsing them would read as agreement.
			name: "a deliberate skip against one that could not run is a coverage gap",
			clusters: []ClusterResult{
				scannedCluster("prod", skipped("C-0260", "Missing network policy")),
				scannedCluster("staging", notEvaluated("C-0260", "Missing network policy")),
			},
			wantPosture: false,
			wantGap:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			divergence := divergenceFor("", tt.clusters...)
			require.Len(t, divergence.Controls, 1)
			control := divergence.Controls[0]

			assert.Equal(t, tt.wantPosture, control.PostureDiverges)
			assert.Equal(t, tt.wantGap, control.CoverageGap)
			if tt.assert != nil {
				tt.assert(t, control)
			}
		})
	}
}

// TestBuildDivergenceCarriesTheControlIdentity checks the row says which
// control it is about, since a control ID on its own sends the reader back to
// the matrix to find out what it means.
func TestBuildDivergenceCarriesTheControlIdentity(t *testing.T) {
	divergence := divergenceFor("",
		scannedCluster("prod", failed("C-0016", "Allow privilege escalation", 2)),
		scannedCluster("staging", passed("C-0016", "Allow privilege escalation")),
	)

	require.Len(t, divergence.Controls, 1)
	control := divergence.Controls[0]
	assert.Equal(t, "C-0016", control.ControlID)
	assert.Equal(t, "Allow privilege escalation", control.Name)
	assert.NotEmpty(t, control.Severity)
}

// TestBuildDivergenceAgainstAReferenceCluster covers the golden cluster case.
// Naming a reference does not change which controls are reported, since the
// reference is one of the clusters and they either disagree or they do not.
// What it adds is the reference's own verdict beside everyone else's.
func TestBuildDivergenceAgainstAReferenceCluster(t *testing.T) {
	clusters := []ClusterResult{
		scannedCluster("prod", passed("C-0016", "Allow privilege escalation")),
		scannedCluster("staging", failed("C-0016", "Allow privilege escalation", 3)),
		scannedCluster("dr", failed("C-0016", "Allow privilege escalation", 1)),
	}

	withReference := divergenceFor("prod", clusters...)
	withoutReference := divergenceFor("", clusters...)

	assert.Equal(t, "prod", withReference.ReferenceCluster)
	assert.False(t, withReference.ReferenceUnavailable)

	require.Len(t, withReference.Controls, 1)
	control := withReference.Controls[0]
	assert.Equal(t, CellPassed, control.ReferenceStatus,
		"the reference's own verdict is what the others are read against")
	assert.Equal(t, []string{"dr", "staging"}, control.Failed,
		"the clusters that differ from the reference are the ones at another outcome")

	require.Len(t, withoutReference.Controls, 1)
	assert.Empty(t, withoutReference.Controls[0].ReferenceStatus,
		"no reference asked for, so no reference verdict")
	assert.Equal(t, control.Passed, withoutReference.Controls[0].Passed,
		"naming a reference must not change which clusters are reported")
}

// TestBuildDivergenceReferenceUnavailable covers a reference that contributed
// nothing. Falling back silently to an unreferenced comparison would leave the
// reader believing they were comparing against a cluster that was never there.
func TestBuildDivergenceReferenceUnavailable(t *testing.T) {
	tests := []struct {
		name     string
		clusters []ClusterResult
	}{
		{
			name: "the reference could not be scanned",
			clusters: []ClusterResult{
				unreachableCluster("golden", "no route to host"),
				scannedCluster("prod", failed("C-0016", "Allow privilege escalation", 2)),
				scannedCluster("staging", passed("C-0016", "Allow privilege escalation")),
			},
		},
		{
			name: "the reference is not in the fleet at all",
			clusters: []ClusterResult{
				scannedCluster("prod", failed("C-0016", "Allow privilege escalation", 2)),
				scannedCluster("staging", passed("C-0016", "Allow privilege escalation")),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			divergence := divergenceFor("golden", tt.clusters...)

			assert.Equal(t, "golden", divergence.ReferenceCluster)
			assert.True(t, divergence.ReferenceUnavailable,
				"a reference that was never measured has to be called out rather than quietly dropped")
			require.Len(t, divergence.Controls, 1, "the clusters still disagree with each other")
			assert.Empty(t, divergence.Controls[0].ReferenceStatus)
		})
	}
}

// TestBuildDivergenceReferenceMissingOneControl covers a reference that was
// scanned but did not look at a particular control. The row still reports the
// disagreement and carries no reference verdict, which is itself the useful
// fact: the cluster being compared against did not check something the others
// did.
func TestBuildDivergenceReferenceMissingOneControl(t *testing.T) {
	divergence := divergenceFor("golden",
		scannedCluster("golden", passed("C-0038", "Host PID/IPC privileges")),
		scannedCluster("prod", failed("C-0016", "Allow privilege escalation", 2)),
		scannedCluster("staging", passed("C-0016", "Allow privilege escalation")),
	)

	assert.False(t, divergence.ReferenceUnavailable, "golden was scanned, it just ran a different control")
	control := controlByID(t, divergence, "C-0016")
	assert.Empty(t, control.ReferenceStatus)
	assert.True(t, control.PostureDiverges)
}

// TestBuildDivergenceIsOrderIndependent guards the whole class of ordering bug
// rather than one instance of it. BuildDivergence is exported and reads a
// matrix whose cells come out of a map, so duplicate cluster IDs, mixed
// outcomes and an absent reference all have to resolve the same way whichever
// order they arrive in. Every permutation of each fleet below has to serialise
// identically.
func TestBuildDivergenceIsOrderIndependent(t *testing.T) {
	tests := map[string][]ClusterResult{
		"clusters at every outcome": {
			scannedCluster("a", passed("C-0016", "Allow privilege escalation")),
			scannedCluster("b", failed("C-0016", "Allow privilege escalation", 1)),
			scannedCluster("c", skipped("C-0016", "Allow privilege escalation")),
			scannedCluster("d", notEvaluated("C-0016", "Allow privilege escalation")),
		},
		"several controls disagreeing at once": {
			scannedCluster("a",
				passed("C-0016", "Allow privilege escalation"),
				failed("C-0038", "Host PID/IPC privileges", 2),
				notEvaluated("C-0260", "Missing network policy"),
			),
			scannedCluster("b",
				failed("C-0016", "Allow privilege escalation", 1),
				failed("C-0038", "Host PID/IPC privileges", 3),
				passed("C-0260", "Missing network policy"),
			),
			scannedCluster("c",
				passed("C-0016", "Allow privilege escalation"),
				passed("C-0038", "Host PID/IPC privileges"),
				skipped("C-0260", "Missing network policy"),
			),
		},
		"clusters sharing an ID": {
			scannedCluster("dup", passed("C-0016", "Allow privilege escalation")),
			scannedCluster("dup", failed("C-0016", "Allow privilege escalation", 1)),
			scannedCluster("other", failed("C-0016", "Allow privilege escalation", 2)),
		},
		"unscanned clusters mixed in": {
			scannedCluster("a", passed("C-0016", "Allow privilege escalation")),
			unreachableCluster("b", "no route to host"),
			scannedCluster("c", failed("C-0016", "Allow privilege escalation", 1)),
			{ClusterID: "d", Context: "d", Status: ClusterCancelled, Error: "context canceled"},
		},
	}

	for name, clusters := range tests {
		t.Run(name, func(t *testing.T) {
			for _, reference := range []string{"", "a", "absent"} {
				var want string
				for _, permuted := range permutations(clusters) {
					got, err := json.Marshal(divergenceFor(reference, permuted...))
					require.NoError(t, err)
					if want == "" {
						want = string(got)
						continue
					}
					assert.JSONEq(t, want, string(got),
						"the divergence changed with the order of its input, reference %q", reference)
				}
			}
		})
	}
}

// TestBuildDivergenceRoundTrips checks the report survives the wire. The struct
// tags are the contract a dashboard reads, so a tag that does not match its
// field would let a row serialise and come back with the clusters missing.
func TestBuildDivergenceRoundTrips(t *testing.T) {
	want := divergenceFor("prod",
		scannedCluster("prod", passed("C-0016", "Allow privilege escalation")),
		scannedCluster("staging", failed("C-0016", "Allow privilege escalation", 3)),
		scannedCluster("dr", notEvaluated("C-0016", "Allow privilege escalation")),
	)

	raw, err := json.Marshal(want)
	require.NoError(t, err)

	var got FleetDivergence
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Equal(t, want, got)
}

// TestBuildDivergenceTrimsTheReferenceCluster covers a caller passing a
// reference padded with whitespace. Stored as given, a blank one would be
// reported as a cluster that could not be scanned, and a padded real name would
// say the cluster was unavailable while it sat in the matrix.
func TestBuildDivergenceTrimsTheReferenceCluster(t *testing.T) {
	clusters := []ClusterResult{
		scannedCluster("prod", passed("C-0016", "Allow privilege escalation")),
		scannedCluster("staging", failed("C-0016", "Allow privilege escalation", 1)),
	}

	blank := divergenceFor("   ", clusters...)
	assert.Empty(t, blank.ReferenceCluster)
	assert.False(t, blank.ReferenceUnavailable,
		"a blank reference means none was asked for, not one that could not be reached")

	padded := divergenceFor("  prod  ", clusters...)
	assert.Equal(t, "prod", padded.ReferenceCluster)
	assert.False(t, padded.ReferenceUnavailable)
	require.Len(t, padded.Controls, 1)
	assert.Equal(t, CellPassed, padded.Controls[0].ReferenceStatus)
	assert.Equal(t, divergenceFor("prod", clusters...), padded)
}
