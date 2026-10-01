package fleet

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scoredCluster is a scanned cluster with a chosen compliance score and
// coverage, which is what the rollup reads.
func scoredCluster(name string, complianceScore, coverageScore float32) ClusterResult {
	cluster := scannedCluster(name, passed("C-0016", "Allow privilege escalation"))
	cluster.ComplianceScore = score(complianceScore)
	cluster.Coverage = &cautils.ScanCoverage{
		CoverageScore: coverageScore,
		Degraded:      coverageScore < 100,
	}
	return cluster
}

// frameworkCluster is a scored cluster that also ran the named frameworks. Any
// name listed in vacuous is recorded in the cluster's coverage the way a real
// scan records it, so the rollup sees the same signal Kubescape produces.
func frameworkCluster(name string, complianceScore, coverageScore float32, scores map[string]float32, vacuous ...string) ClusterResult {
	cluster := scoredCluster(name, complianceScore, coverageScore)

	frameworks := make([]reportsummary.FrameworkSummary, 0, len(scores))
	for frameworkName, value := range scores {
		frameworks = append(frameworks, reportsummary.FrameworkSummary{
			Name:            frameworkName,
			Version:         "v2",
			ComplianceScore: value,
		})
	}
	cluster.Report.SummaryDetails.Frameworks = frameworks
	if len(vacuous) > 0 {
		cluster.Coverage.VacuousFrameworks = vacuous
	}
	return cluster
}

// TestBuildComplianceRollup covers the fleet-wide score and, more importantly,
// which clusters are allowed to produce it. Every case also checks that the
// contributors and the excluded list account for every cluster between them,
// since a rollup that lost track of a cluster would be a score nobody could
// audit.
func TestBuildComplianceRollup(t *testing.T) {
	tests := []struct {
		name        string
		results     []ClusterResult
		minCoverage float32
		wantScore   *float32
		wantScored  int
		wantTotal   int
		assert      func(t *testing.T, rollup ComplianceRollup)
	}{
		{
			name: "every cluster contributes equally",
			results: []ClusterResult{
				scoredCluster("prod", 60, 100),
				scoredCluster("staging", 80, 100),
				scoredCluster("dr", 100, 100),
			},
			wantScore:  score(80),
			wantScored: 3,
			wantTotal:  3,
			assert: func(t *testing.T, rollup ComplianceRollup) {
				t.Helper()
				assert.Empty(t, rollup.Excluded)
			},
		},
		{
			// The case the floor exists for. dr evaluated almost nothing and
			// passed what little it ran, so averaging it in would lift the
			// fleet score on the strength of a scan that barely happened.
			name: "a barely scanned cluster is held back rather than inflating the score",
			results: []ClusterResult{
				scoredCluster("prod", 50, 100),
				scoredCluster("staging", 50, 100),
				scoredCluster("dr", 100, 4),
			},
			minCoverage: 50,
			wantScore:   score(50),
			wantScored:  2,
			wantTotal:   3,
			assert: func(t *testing.T, rollup ComplianceRollup) {
				t.Helper()
				require.Len(t, rollup.Excluded, 1)
				excluded := rollup.Excluded[0]
				assert.Equal(t, "dr", excluded.ClusterID)
				assert.Equal(t, ExcludedLowCoverage, excluded.Reason)
				require.NotNil(t, excluded.Coverage)
				assert.InDelta(t, 4, *excluded.Coverage, 0)
				require.NotNil(t, excluded.ComplianceScore,
					"the uncounted score has to be visible for the exclusion to be auditable")
				assert.InDelta(t, 100, *excluded.ComplianceScore, 0)
			},
		},
		{
			name: "a low-coverage cluster is held back even when it would lower the score",
			results: []ClusterResult{
				scoredCluster("prod", 90, 100),
				scoredCluster("dr", 10, 4),
			},
			minCoverage: 50,
			wantScore:   score(90),
			wantScored:  1,
			wantTotal:   2,
			assert: func(t *testing.T, rollup ComplianceRollup) {
				t.Helper()
				require.Len(t, rollup.Excluded, 1)
				assert.Equal(t, ExcludedLowCoverage, rollup.Excluded[0].Reason,
					"the floor is about how much was measured, not about which way the number moves")
			},
		},
		{
			name: "a cluster exactly at the floor still counts",
			results: []ClusterResult{
				scoredCluster("prod", 40, 50),
				scoredCluster("staging", 60, 100),
			},
			minCoverage: 50,
			wantScore:   score(50),
			wantScored:  2,
			wantTotal:   2,
		},
		{
			name: "no floor lets every scored cluster through",
			results: []ClusterResult{
				scoredCluster("prod", 40, 100),
				scoredCluster("dr", 100, 1),
			},
			wantScore:  score(70),
			wantScored: 2,
			wantTotal:  2,
			assert: func(t *testing.T, rollup ComplianceRollup) {
				t.Helper()
				assert.Empty(t, rollup.Excluded, "an operator who set no floor asked for nothing to be dropped")
				assert.InDelta(t, 0, rollup.MinCoverage, 0)
			},
		},
		{
			name: "unscanned clusters are excluded and named",
			results: []ClusterResult{
				scoredCluster("prod", 70, 100),
				unreachableCluster("dr", "no route to host"),
				{ClusterID: "eu", Context: "eu", Status: ClusterCancelled, Error: "context canceled"},
			},
			wantScore:  score(70),
			wantScored: 1,
			wantTotal:  3,
			assert: func(t *testing.T, rollup ComplianceRollup) {
				t.Helper()
				require.Len(t, rollup.Excluded, 2)
				for _, excluded := range rollup.Excluded {
					assert.Equal(t, ExcludedNotScanned, excluded.Reason)
					assert.Nil(t, excluded.Coverage, "a cluster that never ran has no coverage to report")
					assert.Nil(t, excluded.ComplianceScore)
				}
			},
		},
		{
			name: "a scanned cluster missing its measurements is a gap in the report, not a zero",
			results: func() []ClusterResult {
				noScore := scoredCluster("staging", 80, 100)
				noScore.ComplianceScore = nil
				noCoverage := scoredCluster("dr", 80, 100)
				noCoverage.Coverage = nil
				return []ClusterResult{scoredCluster("prod", 70, 100), noScore, noCoverage}
			}(),
			wantScore:  score(70),
			wantScored: 1,
			wantTotal:  3,
			assert: func(t *testing.T, rollup ComplianceRollup) {
				t.Helper()
				require.Len(t, rollup.Excluded, 2)
				for _, excluded := range rollup.Excluded {
					assert.Equal(t, ExcludedNotScored, excluded.Reason)
				}
			},
		},
		{
			name: "a fleet nothing could be measured in has no score at all",
			results: []ClusterResult{
				unreachableCluster("prod", "no route to host"),
				unreachableCluster("dr", "no route to host"),
			},
			wantScore:  nil,
			wantScored: 0,
			wantTotal:  2,
			assert: func(t *testing.T, rollup ComplianceRollup) {
				t.Helper()
				assert.Nil(t, rollup.ComplianceScore,
					"reporting 0 here would read as fully non-compliant rather than never measured")
				assert.Len(t, rollup.Excluded, 2)
				assert.Empty(t, rollup.Frameworks, "no contributing cluster means no framework rolled up")
			},
		},
		{
			name: "every cluster below the floor leaves no score",
			results: []ClusterResult{
				scoredCluster("prod", 100, 10),
				scoredCluster("dr", 100, 20),
			},
			minCoverage: 50,
			wantScore:   nil,
			wantScored:  0,
			wantTotal:   2,
		},
		{
			name:       "no clusters at all",
			results:    nil,
			wantScore:  nil,
			wantScored: 0,
			wantTotal:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rollup := BuildComplianceRollup(tt.results, tt.minCoverage)

			if tt.wantScore == nil {
				assert.Nil(t, rollup.ComplianceScore)
			} else {
				require.NotNil(t, rollup.ComplianceScore)
				assert.InDelta(t, *tt.wantScore, *rollup.ComplianceScore, 0.001)
			}
			assert.Equal(t, tt.wantScored, rollup.ClustersScored)
			assert.Equal(t, tt.wantTotal, rollup.ClustersTotal)
			assert.InDelta(t, tt.minCoverage, rollup.MinCoverage, 0)
			assert.Equal(t, tt.wantTotal, rollup.ClustersScored+len(rollup.Excluded),
				"every cluster either contributed or is accounted for in Excluded")

			if tt.assert != nil {
				tt.assert(t, rollup)
			}
		})
	}
}

// TestBuildComplianceRollupWeightsClustersEqually pins that the mean is over
// clusters rather than over resources. A cluster with thousands of resources
// and one with a handful each get one vote, because the question is how
// compliant the clusters are, not how compliant the resources are.
func TestBuildComplianceRollupWeightsClustersEqually(t *testing.T) {
	large := scoredCluster("prod", 0, 100)
	large.Report.SummaryDetails.StatusCounters.PassedResources = 10000
	small := scoredCluster("staging", 100, 100)
	small.Report.SummaryDetails.StatusCounters.PassedResources = 1

	rollup := BuildComplianceRollup([]ClusterResult{large, small}, 0)

	require.NotNil(t, rollup.ComplianceScore)
	assert.InDelta(t, 50, *rollup.ComplianceScore, 0.001,
		"one large cluster must not speak for the whole fleet")
}

// TestBuildComplianceRollupOrderIsIndependentOfInput guards the sort on
// Excluded. Without it the list would follow input order, and two rollups of an
// unchanged fleet scanned in a different order would not compare equal.
func TestBuildComplianceRollupOrderIsIndependentOfInput(t *testing.T) {
	forward := BuildComplianceRollup([]ClusterResult{
		unreachableCluster("prod", "no route to host"),
		unreachableCluster("dr", "no route to host"),
		unreachableCluster("eu", "no route to host"),
	}, 0)
	reversed := BuildComplianceRollup([]ClusterResult{
		unreachableCluster("eu", "no route to host"),
		unreachableCluster("dr", "no route to host"),
		unreachableCluster("prod", "no route to host"),
	}, 0)

	assert.Equal(t, forward.Excluded, reversed.Excluded)
	require.Len(t, forward.Excluded, 3)
	assert.Equal(t, "dr", forward.Excluded[0].ClusterID)
	assert.Equal(t, "eu", forward.Excluded[1].ClusterID)
	assert.Equal(t, "prod", forward.Excluded[2].ClusterID)
}

// TestBuildComplianceRollupPerFramework covers the per-framework scores. The
// case that matters is the vacuous one: a framework that reported 100% only
// because nothing of the kind it checks existed must not lift the fleet's
// standing, and the cluster it happened in must be named rather than dropped.
func TestBuildComplianceRollupPerFramework(t *testing.T) {
	tests := []struct {
		name        string
		results     []ClusterResult
		minCoverage float32
		assert      func(t *testing.T, frameworks []FrameworkRollup)
	}{
		{
			name: "each framework is averaged over the clusters that ran it",
			results: []ClusterResult{
				frameworkCluster("prod", 70, 100, map[string]float32{"NSA": 60, "MITRE": 80}),
				frameworkCluster("staging", 70, 100, map[string]float32{"NSA": 40, "MITRE": 100}),
			},
			assert: func(t *testing.T, frameworks []FrameworkRollup) {
				t.Helper()
				require.Len(t, frameworks, 2)
				assert.Equal(t, "MITRE", frameworks[0].Name, "frameworks are sorted by name")
				assert.Equal(t, "NSA", frameworks[1].Name)

				require.NotNil(t, frameworks[1].ComplianceScore)
				assert.InDelta(t, 50, *frameworks[1].ComplianceScore, 0.001)
				assert.Equal(t, 2, frameworks[1].ClustersScored)
				assert.Equal(t, 2, frameworks[1].ClustersReporting)
			},
		},
		{
			// A framework only one cluster ran must not look like a fleet-wide
			// verdict. The counts are what make that visible.
			name: "a framework only one cluster ran says so",
			results: []ClusterResult{
				frameworkCluster("prod", 70, 100, map[string]float32{"NSA": 60, "CIS": 90}),
				frameworkCluster("staging", 70, 100, map[string]float32{"NSA": 40}),
			},
			assert: func(t *testing.T, frameworks []FrameworkRollup) {
				t.Helper()
				require.Len(t, frameworks, 2)
				cis := frameworks[0]
				assert.Equal(t, "CIS", cis.Name)
				require.NotNil(t, cis.ComplianceScore)
				assert.InDelta(t, 90, *cis.ComplianceScore, 0.001)
				assert.Equal(t, 1, cis.ClustersScored, "only prod ran CIS")
				assert.Equal(t, 1, cis.ClustersReporting)
			},
		},
		{
			// The point of reading VacuousFrameworks. staging found no resource
			// of the kind NSA checks, so its 100 measures nothing. Averaging it
			// would report the fleet at 80 on NSA when one real measurement
			// said 60.
			name: "a vacuous framework score is left out and the cluster named",
			results: []ClusterResult{
				frameworkCluster("prod", 70, 100, map[string]float32{"NSA": 60}),
				frameworkCluster("staging", 70, 100, map[string]float32{"NSA": 100}, "NSA"),
			},
			assert: func(t *testing.T, frameworks []FrameworkRollup) {
				t.Helper()
				require.Len(t, frameworks, 1)
				nsa := frameworks[0]
				require.NotNil(t, nsa.ComplianceScore)
				assert.InDelta(t, 60, *nsa.ComplianceScore, 0.001,
					"a framework that checked nothing must not raise the fleet's standing")
				assert.Equal(t, 1, nsa.ClustersScored)
				assert.Equal(t, 2, nsa.ClustersReporting,
					"staging did run it, which is worth knowing even though its result did not count")
				assert.Equal(t, []string{"staging"}, nsa.VacuousIn)
			},
		},
		{
			name: "a framework vacuous everywhere has no score at all",
			results: []ClusterResult{
				frameworkCluster("prod", 70, 100, map[string]float32{"NSA": 100}, "NSA"),
				frameworkCluster("staging", 70, 100, map[string]float32{"NSA": 100}, "NSA"),
			},
			assert: func(t *testing.T, frameworks []FrameworkRollup) {
				t.Helper()
				require.Len(t, frameworks, 1)
				assert.Nil(t, frameworks[0].ComplianceScore,
					"nothing was measured, so reporting 100 would be the exact misreading this guards")
				assert.Equal(t, 0, frameworks[0].ClustersScored)
				assert.Equal(t, 2, frameworks[0].ClustersReporting)
				assert.Equal(t, []string{"prod", "staging"}, frameworks[0].VacuousIn)
			},
		},
		{
			// A cluster held back from the headline number is no better a
			// witness to a single framework than to the fleet as a whole.
			name: "a cluster below the coverage floor contributes to no framework either",
			results: []ClusterResult{
				frameworkCluster("prod", 70, 100, map[string]float32{"NSA": 60}),
				frameworkCluster("dr", 100, 4, map[string]float32{"NSA": 100}),
			},
			minCoverage: 50,
			assert: func(t *testing.T, frameworks []FrameworkRollup) {
				t.Helper()
				require.Len(t, frameworks, 1)
				require.NotNil(t, frameworks[0].ComplianceScore)
				assert.InDelta(t, 60, *frameworks[0].ComplianceScore, 0.001)
				assert.Equal(t, 1, frameworks[0].ClustersReporting,
					"dr never reached the framework rollup at all")
			},
		},
		{
			name: "an unnamed framework is not rolled up",
			results: []ClusterResult{
				frameworkCluster("prod", 70, 100, map[string]float32{"": 50, "NSA": 60}),
			},
			assert: func(t *testing.T, frameworks []FrameworkRollup) {
				t.Helper()
				require.Len(t, frameworks, 1)
				assert.Equal(t, "NSA", frameworks[0].Name)
			},
		},
		{
			name: "clusters with no frameworks produce no rollup",
			results: []ClusterResult{
				scoredCluster("prod", 70, 100),
				scoredCluster("staging", 70, 100),
			},
			assert: func(t *testing.T, frameworks []FrameworkRollup) {
				t.Helper()
				assert.Empty(t, frameworks)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rollup := BuildComplianceRollup(tt.results, tt.minCoverage)
			tt.assert(t, rollup.Frameworks)
		})
	}
}

// TestBuildComplianceRollupFrameworkOrderIsIndependentOfInput guards the sorts
// in the framework rollup. The frameworks are accumulated in a map and the
// vacuous list follows cluster order, so without both sorts two rollups of an
// unchanged fleet would not compare equal.
func TestBuildComplianceRollupFrameworkOrderIsIndependentOfInput(t *testing.T) {
	scores := map[string]float32{"NSA": 60, "MITRE": 70, "CIS": 80, "SOC2": 90}
	forward := []ClusterResult{
		frameworkCluster("prod", 70, 100, scores, "SOC2"),
		frameworkCluster("staging", 70, 100, scores, "SOC2"),
	}
	reversed := []ClusterResult{
		frameworkCluster("staging", 70, 100, scores, "SOC2"),
		frameworkCluster("prod", 70, 100, scores, "SOC2"),
	}

	// Repeated so a run that happened to hash in the right order cannot pass by
	// luck, the same way the control matrix guards its own sort.
	for i := 0; i < 20; i++ {
		assert.Equal(t, BuildComplianceRollup(forward, 0).Frameworks,
			BuildComplianceRollup(reversed, 0).Frameworks, "iteration %d", i)
	}

	got := BuildComplianceRollup(forward, 0).Frameworks
	names := make([]string, 0, len(got))
	for _, framework := range got {
		names = append(names, framework.Name)
	}
	assert.Equal(t, []string{"CIS", "MITRE", "NSA", "SOC2"}, names)
	assert.Equal(t, []string{"prod", "staging"}, got[3].VacuousIn)
}

// TestBuildComplianceRollupCountsEachClusterOncePerFramework guards the
// equal-weighting rule from the inside. A report listing the same framework
// twice would otherwise let that one cluster vote twice on it.
func TestBuildComplianceRollupCountsEachClusterOncePerFramework(t *testing.T) {
	duplicated := scoredCluster("prod", 70, 100)
	duplicated.Report.SummaryDetails.Frameworks = []reportsummary.FrameworkSummary{
		{Name: "NSA", Version: "v2", ComplianceScore: 0},
		{Name: "NSA", Version: "v2", ComplianceScore: 0},
	}
	other := frameworkCluster("staging", 70, 100, map[string]float32{"NSA": 100})

	rollup := BuildComplianceRollup([]ClusterResult{duplicated, other}, 0)

	require.Len(t, rollup.Frameworks, 1)
	nsa := rollup.Frameworks[0]
	require.NotNil(t, nsa.ComplianceScore)
	assert.InDelta(t, 50, *nsa.ComplianceScore, 0.001,
		"prod must weigh once, not twice, however many times its report names the framework")
	assert.Equal(t, 2, nsa.ClustersScored)
	assert.Equal(t, 2, nsa.ClustersReporting)
}

// TestBuildComplianceRollupRejectsScoresThatAreNotNumbers covers what a score
// that is not a number would otherwise do to the rollup.
//
// A NaN in the sum makes the mean NaN, so one cluster would decide the score
// for every other. A NaN coverage is worse: it compares false against
// everything, so that cluster would pass the floor rather than be held back by
// it, which is the opposite of what the floor is for.
func TestBuildComplianceRollupRejectsScoresThatAreNotNumbers(t *testing.T) {
	nan := float32(math.NaN())
	inf := float32(math.Inf(1))

	tests := []struct {
		name    string
		broken  ClusterResult
		reason  string
		wantAvg float32
	}{
		{
			name:   "compliance score is NaN",
			broken: scoredCluster("dr", nan, 100),
		},
		{
			name:   "compliance score is infinite",
			broken: scoredCluster("dr", inf, 100),
		},
		{
			name:   "coverage is NaN",
			broken: scoredCluster("dr", 100, nan),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rollup := BuildComplianceRollup([]ClusterResult{
				scoredCluster("prod", 60, 100),
				tt.broken,
			}, 50)

			require.NotNil(t, rollup.ComplianceScore)
			assert.InDelta(t, 60, *rollup.ComplianceScore, 0.001,
				"the fleet score must come from the one cluster that reported a number")
			assert.Equal(t, 1, rollup.ClustersScored)
			require.Len(t, rollup.Excluded, 1)
			assert.Equal(t, "dr", rollup.Excluded[0].ClusterID)
			assert.Equal(t, ExcludedNotScored, rollup.Excluded[0].Reason,
				"a value that is not a number is not a measurement, so it is treated as missing")

			raw, err := json.Marshal(rollup)
			require.NoError(t, err, "the rollup has to survive marshalling, or the whole fleet report is lost")
			assert.NotContains(t, string(raw), "NaN")
			assert.NotContains(t, string(raw), "Inf")
		})
	}
}

// TestBuildComplianceRollupRejectsFrameworkScoresThatAreNotNumbers is the same
// guard one level down. A framework score that is not a number is skipped, and
// the gap between ClustersReporting and ClustersScored is what shows it.
func TestBuildComplianceRollupRejectsFrameworkScoresThatAreNotNumbers(t *testing.T) {
	broken := frameworkCluster("staging", 70, 100, map[string]float32{"NSA": float32(math.NaN())})
	rollup := BuildComplianceRollup([]ClusterResult{
		frameworkCluster("prod", 70, 100, map[string]float32{"NSA": 60}),
		broken,
	}, 0)

	require.Len(t, rollup.Frameworks, 1)
	nsa := rollup.Frameworks[0]
	require.NotNil(t, nsa.ComplianceScore)
	assert.InDelta(t, 60, *nsa.ComplianceScore, 0.001)
	assert.Equal(t, 1, nsa.ClustersScored)
	assert.Equal(t, 2, nsa.ClustersReporting, "staging ran it, its number just was not usable")

	raw, err := json.Marshal(rollup)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "NaN")
}

// TestBuildComplianceRollupDoesNotAliasTheCallersData pins that the figures
// carried on an excluded cluster are copies. Sharing the caller's pointers
// would let a later write to the results change what the report says.
func TestBuildComplianceRollupDoesNotAliasTheCallersData(t *testing.T) {
	cluster := scoredCluster("dr", 100, 5)
	rollup := BuildComplianceRollup([]ClusterResult{cluster}, 50)

	require.Len(t, rollup.Excluded, 1)
	excluded := rollup.Excluded[0]
	require.NotNil(t, excluded.Coverage)
	require.NotNil(t, excluded.ComplianceScore)

	*cluster.ComplianceScore = 0
	cluster.Coverage.CoverageScore = 0

	assert.InDelta(t, 100, *excluded.ComplianceScore, 0, "the report must not change under the caller's feet")
	assert.InDelta(t, 5, *excluded.Coverage, 0)
}

// TestBuildComplianceRollupLeavesItsInputAlone pins that building a rollup is a
// read. A caller printing the results afterwards must see what it passed in.
func TestBuildComplianceRollupLeavesItsInputAlone(t *testing.T) {
	results := []ClusterResult{
		scoredCluster("prod", 60, 100),
		scoredCluster("dr", 100, 5),
		unreachableCluster("eu", "no route to host"),
	}
	before, err := json.Marshal(results)
	require.NoError(t, err)

	BuildComplianceRollup(results, 50)

	after, err := json.Marshal(results)
	require.NoError(t, err)
	assert.JSONEq(t, string(before), string(after))
}

// TestBuildComplianceRollupFloorThatIsNotANumber covers a coverage floor that
// is not a real number. It cannot hold anything back, since every comparison
// against it is false, so it is recorded as the no floor it already behaves as
// rather than being stored and breaking the report's encoding.
func TestBuildComplianceRollupFloorThatIsNotANumber(t *testing.T) {
	for _, floor := range []float32{float32(math.NaN()), float32(math.Inf(1)), float32(math.Inf(-1))} {
		rollup := BuildComplianceRollup([]ClusterResult{
			scoredCluster("prod", 60, 100),
			scoredCluster("dr", 100, 5),
		}, floor)

		assert.InDelta(t, 0, rollup.MinCoverage, 0)
		assert.Empty(t, rollup.Excluded)
		assert.Equal(t, 2, rollup.ClustersScored)

		raw, err := json.Marshal(rollup)
		require.NoError(t, err, "a floor that is not a number must not stop the report encoding")
		assert.NotContains(t, string(raw), "NaN")
		assert.NotContains(t, string(raw), "Inf")
	}
}

// TestBuildComplianceRollupOrdersDuplicateClusterIDs covers results that share
// a cluster ID but differ in why they were excluded. Sorting on the ID alone
// would leave their order down to the order they arrived in.
func TestBuildComplianceRollupOrdersDuplicateClusterIDs(t *testing.T) {
	duplicate := func(reason ExclusionReason) ClusterResult {
		switch reason {
		case ExcludedNotScanned:
			return unreachableCluster("dup", "no route to host")
		case ExcludedLowCoverage:
			return scoredCluster("dup", 100, 5)
		default:
			missing := scoredCluster("dup", 80, 100)
			missing.ComplianceScore = nil
			return missing
		}
	}
	reasons := []ExclusionReason{ExcludedLowCoverage, ExcludedNotScanned, ExcludedNotScored}

	forward := BuildComplianceRollup([]ClusterResult{
		duplicate(reasons[0]), duplicate(reasons[1]), duplicate(reasons[2]),
	}, 50)
	reversed := BuildComplianceRollup([]ClusterResult{
		duplicate(reasons[2]), duplicate(reasons[1]), duplicate(reasons[0]),
	}, 50)

	assert.Equal(t, forward.Excluded, reversed.Excluded)
	require.Len(t, forward.Excluded, 3)
	assert.Equal(t, ExcludedLowCoverage, forward.Excluded[0].Reason)
	assert.Equal(t, ExcludedNotScanned, forward.Excluded[1].Reason)
	assert.Equal(t, ExcludedNotScored, forward.Excluded[2].Reason)
}

// TestBuildComplianceRollupOrdersDuplicatesByMeasurement is the same guard one
// level further down, for entries that agree on both cluster ID and reason and
// differ only in the figures they carry.
func TestBuildComplianceRollupOrdersDuplicatesByMeasurement(t *testing.T) {
	low := func(coverage float32) ClusterResult { return scoredCluster("dup", 100, coverage) }

	forward := BuildComplianceRollup([]ClusterResult{low(5), low(20), low(12)}, 50)
	reversed := BuildComplianceRollup([]ClusterResult{low(12), low(20), low(5)}, 50)

	assert.Equal(t, forward.Excluded, reversed.Excluded)
	require.Len(t, forward.Excluded, 3)
	assert.InDelta(t, 5, *forward.Excluded[0].Coverage, 0)
	assert.InDelta(t, 12, *forward.Excluded[1].Coverage, 0)
	assert.InDelta(t, 20, *forward.Excluded[2].Coverage, 0)
}

// TestBuildComplianceRollupResolvesDuplicateFrameworksByValue covers a report
// naming the same framework more than once with different scores. One cluster
// gets one vote, so the lowest score is taken rather than whichever came first,
// because position depends on how the report was written and the value does not.
func TestBuildComplianceRollupResolvesDuplicateFrameworksByValue(t *testing.T) {
	duplicate := func(scores ...float32) ClusterResult {
		cluster := scoredCluster("prod", 70, 100)
		frameworks := make([]reportsummary.FrameworkSummary, 0, len(scores))
		for _, value := range scores {
			frameworks = append(frameworks, reportsummary.FrameworkSummary{
				Name: "NSA", Version: "v2", ComplianceScore: value,
			})
		}
		cluster.Report.SummaryDetails.Frameworks = frameworks
		return cluster
	}
	other := frameworkCluster("staging", 70, 100, map[string]float32{"NSA": 50})

	forward := BuildComplianceRollup([]ClusterResult{duplicate(90, 30, 60), other}, 0)
	reversed := BuildComplianceRollup([]ClusterResult{duplicate(60, 30, 90), other}, 0)

	assert.Equal(t, forward.Frameworks, reversed.Frameworks,
		"which duplicate wins must not depend on the order the report lists them in")

	require.Len(t, forward.Frameworks, 1)
	nsa := forward.Frameworks[0]
	require.NotNil(t, nsa.ComplianceScore)
	assert.InDelta(t, 40, *nsa.ComplianceScore, 0.001,
		"prod's lowest of 30 averaged with staging's 50")
	assert.Equal(t, 2, nsa.ClustersScored)
	assert.Equal(t, 2, nsa.ClustersReporting)
}

// TestBuildComplianceRollupDuplicateFrameworkWithUnusableScore covers
// duplicates where some scores are not numbers. The usable ones still decide
// the result, and the framework only loses its score when none of them are.
func TestBuildComplianceRollupDuplicateFrameworkWithUnusableScore(t *testing.T) {
	withScores := func(scores ...float32) ClusterResult {
		cluster := scoredCluster("prod", 70, 100)
		frameworks := make([]reportsummary.FrameworkSummary, 0, len(scores))
		for _, value := range scores {
			frameworks = append(frameworks, reportsummary.FrameworkSummary{Name: "NSA", ComplianceScore: value})
		}
		cluster.Report.SummaryDetails.Frameworks = frameworks
		return cluster
	}
	nan := float32(math.NaN())

	usable := BuildComplianceRollup([]ClusterResult{withScores(nan, 30)}, 0)
	require.Len(t, usable.Frameworks, 1)
	require.NotNil(t, usable.Frameworks[0].ComplianceScore)
	assert.InDelta(t, 30, *usable.Frameworks[0].ComplianceScore, 0.001,
		"the one real number is used rather than the framework being dropped")
	assert.Equal(t, 1, usable.Frameworks[0].ClustersScored)

	none := BuildComplianceRollup([]ClusterResult{withScores(nan, nan)}, 0)
	require.Len(t, none.Frameworks, 1)
	assert.Nil(t, none.Frameworks[0].ComplianceScore)
	assert.Equal(t, 0, none.Frameworks[0].ClustersScored)
	assert.Equal(t, 1, none.Frameworks[0].ClustersReporting)
}

// TestBuildComplianceRollupIsOrderIndependent is the guard for the whole class
// of ordering bug rather than for one instance of it. BuildComplianceRollup is
// exported and takes whatever a caller hands it, so duplicate cluster IDs,
// duplicate framework names and scores that are not numbers all have to resolve
// the same way whichever order they arrive in. Every permutation of each case
// below has to serialise identically.
func TestBuildComplianceRollupIsOrderIndependent(t *testing.T) {
	nan := float32(math.NaN())
	framework := func(name string, value float32) reportsummary.FrameworkSummary {
		return reportsummary.FrameworkSummary{Name: name, ComplianceScore: value}
	}
	withFrameworks := func(id string, vacuous []string, frameworks ...reportsummary.FrameworkSummary) ClusterResult {
		cluster := scoredCluster(id, 70, 100)
		cluster.Report.SummaryDetails.Frameworks = frameworks
		cluster.Coverage.VacuousFrameworks = vacuous
		return cluster
	}

	tests := map[string][]ClusterResult{
		"duplicate framework names with different scores": {
			withFrameworks("a", nil, framework("NSA", 60), framework("NSA", 40), framework("NSA", 90)),
			withFrameworks("b", nil, framework("NSA", 50)),
		},
		"duplicate framework where one score is not a number": {
			withFrameworks("a", nil, framework("NSA", nan), framework("NSA", 30)),
			withFrameworks("b", nil, framework("NSA", 50)),
		},
		"duplicate cluster IDs with different reasons": {
			unreachableCluster("dup", "no route to host"),
			scoredCluster("dup", 100, 5),
			scoredCluster("dup", 60, 100),
		},
		"duplicate cluster IDs excluded for the same reason": {
			scoredCluster("dup", 100, 5), scoredCluster("dup", 20, 11), scoredCluster("dup", 60, 3),
		},
		"unnamed frameworks mixed in": {
			withFrameworks("a", nil, framework("", 10), framework("NSA", 60), framework("", 20)),
		},
		"vacuous naming a framework twice and one never run": {
			withFrameworks("a", []string{"MITRE", "MITRE", "GHOST"}, framework("NSA", 60), framework("MITRE", 70)),
			withFrameworks("b", nil, framework("NSA", 40)),
		},
	}

	for name, results := range tests {
		t.Run(name, func(t *testing.T) {
			var want string
			for _, permuted := range permutations(results) {
				got, err := json.Marshal(BuildComplianceRollup(permuted, 50))
				require.NoError(t, err)
				if want == "" {
					want = string(got)
					continue
				}
				assert.JSONEq(t, want, string(got), "the rollup changed with the order of its input")
			}
		})
	}
}

// permutations returns every ordering of results.
func permutations(results []ClusterResult) [][]ClusterResult {
	if len(results) <= 1 {
		return [][]ClusterResult{results}
	}
	var all [][]ClusterResult
	for i := range results {
		rest := make([]ClusterResult, 0, len(results)-1)
		rest = append(rest, results[:i]...)
		rest = append(rest, results[i+1:]...)
		for _, tail := range permutations(rest) {
			all = append(all, append([]ClusterResult{results[i]}, tail...))
		}
	}
	return all
}
