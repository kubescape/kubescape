package fleet

import (
	"cmp"
	"math"
	"slices"
	"sort"
)

// ComplianceRollup is the fleet's compliance score plus a record of where it
// came from.
//
// The record matters as much as the score. One number for a whole fleet is easy
// to misread, so this also carries how many clusters went into it, how many
// clusters there were in total, and the name and reason for every cluster left
// out. Three clusters out of thirty should not look the same as thirty out of
// thirty.
type ComplianceRollup struct {
	// ComplianceScore is the mean compliance score across contributing
	// clusters, or nil when none contributed.
	//
	// Pointer for the same reason as everywhere else in this package. If
	// nothing could be measured there is no score, and writing 0 would say
	// "fully non-compliant" when the truth is "never measured".
	ComplianceScore *float32 `json:"complianceScore,omitempty"`
	// ClustersScored is how many clusters contributed to ComplianceScore.
	ClustersScored int `json:"clustersScored"`
	// ClustersTotal is how many clusters the report covers, contributing or
	// not.
	ClustersTotal int `json:"clustersTotal"`
	// MinCoverage is the coverage floor that was applied. Zero means no floor,
	// so no cluster was held back for coverage.
	MinCoverage float32 `json:"minCoverage"`
	// Frameworks is the same rollup per framework, over the same contributing
	// clusters, sorted by name.
	Frameworks []FrameworkRollup `json:"frameworks,omitempty"`
	// Excluded names every cluster that did not contribute, sorted by cluster
	// ID so two rollups of an unchanged fleet compare equal.
	Excluded []ExcludedCluster `json:"excluded,omitempty"`
}

// FrameworkRollup is one framework's score across the fleet.
//
// The overall score is not enough on its own. What people usually want to know
// is whether the fleet meets a particular standard, and if two clusters were
// scanned against different framework sets their overall scores are not
// measuring the same thing anyway. Averaging those together compares NSA
// against MITRE. Splitting by framework avoids that.
type FrameworkRollup struct {
	// Name is the framework's name. Clusters can disagree on Version, and this
	// rolls up by name only. Keying on both would split one framework into
	// several rows over a version difference, which hides more than it shows.
	// BuildControlMatrix does the same with a control's name and severity.
	Name string `json:"name"`
	// ComplianceScore is the mean across clusters that scored this framework,
	// or nil when none did.
	ComplianceScore *float32 `json:"complianceScore,omitempty"`
	// ClustersScored is how many clusters contributed to this framework's
	// score.
	ClustersScored int `json:"clustersScored"`
	// ClustersReporting is how many contributing clusters ran this framework at
	// all. It is never below ClustersScored, and is higher when a cluster's
	// result was vacuous. Without both numbers you cannot tell two clusters
	// disagreeing from one cluster measuring and another only looking like it
	// did.
	ClustersReporting int `json:"clustersReporting"`
	// VacuousIn names the clusters where this framework scored 100% only
	// because every control in it was irrelevant, and whose score was
	// therefore left out. Sorted by cluster ID.
	VacuousIn []string `json:"vacuousIn,omitempty"`
}

// ExclusionReason says why a cluster did not contribute to the fleet score.
//
// They are separate values because you would act differently on each. A cluster
// that was never scanned is something to go and fix. A scanned cluster with no
// score is a gap in the report itself. A cluster held back for coverage was
// measured fine, just not enough of it to be worth averaging in. With one
// shared "excluded" value you could not tell a broken fleet from a strict
// floor.
type ExclusionReason string

// The three reasons a cluster can be left out. Every ExcludedCluster carries
// exactly one of them.
const (
	// ExcludedNotScanned is a cluster with no usable report: unreachable,
	// errored, or cancelled before it ran.
	ExcludedNotScanned ExclusionReason = "notScanned"
	// ExcludedNotScored is a cluster that was scanned but is missing its
	// compliance score or its coverage, so there is nothing to average.
	ExcludedNotScored ExclusionReason = "notScored"
	// ExcludedLowCoverage is a cluster whose scan was too incomplete to speak
	// for itself, held back by the MinCoverage floor.
	ExcludedLowCoverage ExclusionReason = "lowCoverage"
)

// ExcludedCluster is one cluster left out of the fleet score.
type ExcludedCluster struct {
	ClusterID string          `json:"clusterID"`
	Reason    ExclusionReason `json:"reason"`
	// Coverage and ComplianceScore are what the cluster reported but did not
	// get counted. Only set for ExcludedLowCoverage, since that is the only
	// case where the cluster had both. They are here so the exclusion can be
	// checked: you can see how far short the scan fell and which way the fleet
	// score would have gone.
	Coverage        *float32 `json:"coverage,omitempty"`
	ComplianceScore *float32 `json:"complianceScore,omitempty"`
}

// BuildComplianceRollup computes the fleet's compliance score from per-cluster
// results, holding back any cluster whose coverage is below minCoverage.
//
// Clusters are weighted equally rather than by size. A fleet score answers "how
// compliant are my clusters", not "how compliant are my resources", and
// weighting by resource count would let one large cluster speak for all the
// others. A consumer wanting the resource-weighted figure has every cluster's
// own report to compute it from.
//
// The coverage floor is there because a compliance score is only worth as much
// as the scan behind it. A cluster that evaluated two controls and passed both
// reports 100, and letting that into the average makes the fleet look better
// than it is. The floor applies either way round, whether the cluster would
// raise the number or lower it, because the problem is the measurement and not
// the direction it points.
//
// A minCoverage of zero means no floor. That is deliberate rather than a
// guessed threshold. The operator decides what coverage they will stand behind,
// and picking a number here would drop clusters they never asked to drop.
func BuildComplianceRollup(results []ClusterResult, minCoverage float32) ComplianceRollup {
	if !usableScore(minCoverage) {
		// A floor that is not a real number cannot hold anything back, since
		// every comparison against it is false, so it is recorded as the no
		// floor it already behaves as.
		minCoverage = 0
	}

	rollup := ComplianceRollup{
		ClustersTotal: len(results),
		MinCoverage:   minCoverage,
	}

	// Accumulated in float64 so a large fleet does not lose precision to
	// repeated float32 addition before the mean is taken.
	var total float64
	contributors := make([]*ClusterResult, 0, len(results))

	for i := range results {
		cluster := &results[i]

		switch {
		case !cluster.Scanned():
			rollup.Excluded = append(rollup.Excluded, ExcludedCluster{
				ClusterID: cluster.ClusterID,
				Reason:    ExcludedNotScanned,
			})
		case !cluster.Scored(), !usableScore(*cluster.ComplianceScore),
			!usableScore(cluster.Coverage.CoverageScore):
			// A score that is not a finite number is not a measurement, so it
			// is treated the same as a missing one. It would otherwise poison
			// the mean, and a NaN coverage would slip past the floor below,
			// since every comparison with NaN is false.
			rollup.Excluded = append(rollup.Excluded, ExcludedCluster{
				ClusterID: cluster.ClusterID,
				Reason:    ExcludedNotScored,
			})
		case cluster.Coverage.CoverageScore < minCoverage:
			coverage := cluster.Coverage.CoverageScore
			score := *cluster.ComplianceScore
			rollup.Excluded = append(rollup.Excluded, ExcludedCluster{
				ClusterID:       cluster.ClusterID,
				Reason:          ExcludedLowCoverage,
				Coverage:        &coverage,
				ComplianceScore: &score,
			})
		default:
			total += float64(*cluster.ComplianceScore)
			rollup.ClustersScored++
			contributors = append(contributors, cluster)
		}
	}

	if rollup.ClustersScored > 0 {
		mean := float32(total / float64(rollup.ClustersScored))
		rollup.ComplianceScore = &mean
	}

	rollup.Frameworks = buildFrameworkRollups(contributors)

	// Ordered on every field, so that results carrying a duplicate cluster ID
	// still serialise the same way whatever order they arrive in.
	sort.SliceStable(rollup.Excluded, func(i, j int) bool {
		a, b := &rollup.Excluded[i], &rollup.Excluded[j]
		if a.ClusterID != b.ClusterID {
			return a.ClusterID < b.ClusterID
		}
		if a.Reason != b.Reason {
			return a.Reason < b.Reason
		}
		if by := compareOptionalScore(a.Coverage, b.Coverage); by != 0 {
			return by < 0
		}
		return compareOptionalScore(a.ComplianceScore, b.ComplianceScore) < 0
	})

	return rollup
}

// frameworkAccumulator gathers one framework's figures while the clusters are
// walked, before the mean is taken.
type frameworkAccumulator struct {
	total     float64
	scored    int
	reporting int
	vacuousIn []string
}

// buildFrameworkRollups rolls each framework up across the clusters that
// contributed to the fleet score.
//
// It walks the contributors, not every result, so a cluster held back from the
// overall score is held back here too. If a cluster was scanned too
// incompletely to count towards compliance, it is no better a witness to how
// one framework did.
//
// A framework's score is skipped in any cluster where it was vacuous, meaning
// it came out at 100% only because every control in it was irrelevant and no
// resource of the kind it checks existed. Kubescape works that out per cluster
// already, in ScanCoverage.VacuousFrameworks. Averaging one in would raise the
// fleet's score on the basis that nothing was checked. The clusters it happened
// in go in VacuousIn rather than being dropped quietly, because a framework
// that is vacuous across most of a fleet is worth knowing about on its own.
func buildFrameworkRollups(contributors []*ClusterResult) []FrameworkRollup {
	accumulators := make(map[string]*frameworkAccumulator)

	for _, cluster := range contributors {
		vacuous := vacuousFrameworkSet(cluster)
		names, scores := clusterFrameworkScores(cluster)

		for _, name := range names {
			accumulator, ok := accumulators[name]
			if !ok {
				accumulator = &frameworkAccumulator{}
				accumulators[name] = accumulator
			}
			accumulator.reporting++

			if _, isVacuous := vacuous[name]; isVacuous {
				accumulator.vacuousIn = append(accumulator.vacuousIn, cluster.ClusterID)
				continue
			}

			score, ok := scores[name]
			if !ok {
				// No usable number for it in this cluster. It still counts
				// towards ClustersReporting, so the gap between that and
				// ClustersScored shows it was dropped.
				continue
			}
			accumulator.total += float64(score)
			accumulator.scored++
		}
	}

	if len(accumulators) == 0 {
		return nil
	}

	rollups := make([]FrameworkRollup, 0, len(accumulators))
	for name, accumulator := range accumulators {
		rollup := FrameworkRollup{
			Name:              name,
			ClustersScored:    accumulator.scored,
			ClustersReporting: accumulator.reporting,
			VacuousIn:         accumulator.vacuousIn,
		}
		if accumulator.scored > 0 {
			mean := float32(accumulator.total / float64(accumulator.scored))
			rollup.ComplianceScore = &mean
		}
		slices.Sort(rollup.VacuousIn)
		rollups = append(rollups, rollup)
	}

	// Accumulated in a map, so sorted here for the same reason the control
	// matrix sorts its rows: without it two reports of an unchanged fleet would
	// not compare equal.
	sort.SliceStable(rollups, func(i, j int) bool {
		return rollups[i].Name < rollups[j].Name
	})

	return rollups
}

// compareOptionalScore orders two scores that may be absent, sorting an absent
// score before a present one.
func compareOptionalScore(a, b *float32) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	default:
		return cmp.Compare(*a, *b)
	}
}

// usableScore reports whether a score is a finite number, and so whether it can
// be averaged or compared against a floor.
//
// Two things go wrong without this. A NaN in the sum makes the mean NaN, so one
// cluster decides the fleet's score for every other. And NaN compares false
// against everything, so a cluster whose coverage is NaN would pass the floor
// instead of being held back by it.
//
// This does not make the report as a whole safe against a bad float. A NaN
// anywhere inside a cluster's embedded PostureReport still fails to marshal,
// but that is true of a single-cluster scan's own JSON output as well and is
// not something the aggregation introduced or can fix from here.
func usableScore(score float32) bool {
	return !math.IsNaN(float64(score)) && !math.IsInf(float64(score), 0)
}

// clusterFrameworkScores reduces one cluster's framework summaries to a single
// score per framework, returning the names in the order the report lists them
// and the scores keyed by name. A framework with no usable score is present in
// names but absent from scores.
//
// One cluster gets one vote per framework, so a report naming the same
// framework more than once has to resolve to one number. The lowest is taken
// rather than whichever happens to come first: position depends on the order
// the report was written in, the value does not, and a contradictory report
// should not end up reporting the more flattering of the two figures.
func clusterFrameworkScores(cluster *ClusterResult) (names []string, scores map[string]float32) {
	frameworks := cluster.Report.SummaryDetails.Frameworks
	names = make([]string, 0, len(frameworks))
	scores = make(map[string]float32, len(frameworks))
	seen := make(map[string]struct{}, len(frameworks))

	for i := range frameworks {
		framework := &frameworks[i]
		if framework.Name == "" {
			// A framework with no name cannot be rolled up with its
			// counterpart in another cluster, and an empty row would say
			// nothing to a reader.
			continue
		}
		if _, ok := seen[framework.Name]; !ok {
			seen[framework.Name] = struct{}{}
			names = append(names, framework.Name)
		}
		if !usableScore(framework.ComplianceScore) {
			continue
		}
		if current, ok := scores[framework.Name]; !ok || framework.ComplianceScore < current {
			scores[framework.Name] = framework.ComplianceScore
		}
	}

	return names, scores
}

// vacuousFrameworkSet is the set of framework names the cluster's own scan
// flagged as vacuous, for lookup while its frameworks are walked.
func vacuousFrameworkSet(cluster *ClusterResult) map[string]struct{} {
	if cluster.Coverage == nil || len(cluster.Coverage.VacuousFrameworks) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(cluster.Coverage.VacuousFrameworks))
	for _, name := range cluster.Coverage.VacuousFrameworks {
		set[name] = struct{}{}
	}
	return set
}
