package attackpath

import (
	"slices"

	"github.com/kubescape/kubescape/v4/core/pkg/vulnexposure"
)

// ScorePath computes a risk score in [0, 10] for one AttackPath.
// The formula is documented here so it is auditable; the factors are also
// emitted in JSON output (Phase 3) so rankings are not a black box.
//
// Factors:
//   - CVE severity on the path:    Critical=4, High=3, Medium=2, Low=1, none=0
//   - Sink is ClusterAdmin:        +2
//   - Path is fully Certain:       +1
//   - Shorter path (fewer edges):  +1 when ≤ 3 edges, +0.5 when ≤ 5
//   - CVE fix available:           +0.5 (more actionable)
//
// A path with no edges scores 0: it connects nothing.
// Raw sum is capped at 10.
func ScorePath(p AttackPath) float64 {
	if len(p.Edges) == 0 {
		return 0
	}
	var score float64

	// CVE severity factor.
	score += cveSeverityPoints(p.CVESeverity)

	// Sink factor: does this path reach ClusterAdmin?
	if slices.ContainsFunc(p.Nodes, func(n Node) bool { return n.Kind == NodeClusterAdmin }) {
		score += 2
	}

	// Certainty factor.
	if p.Certain {
		score += 1
	}

	// Hop count factor (shorter = more actionable).
	switch {
	case len(p.Edges) <= 3:
		score += 1
	case len(p.Edges) <= 5:
		score += 0.5
	}

	// Fix-available factor: a fixable CVE on an exposed workload is the
	// most actionable class of finding this analysis produces.
	if p.CVESeverity != "" && p.CVEFixAvailable {
		score += 0.5
	}

	if score > 10 {
		score = 10
	}
	return score
}

// cveSeverityPoints maps a severity name to the documented 0-4 scale.
// It does not use vulnexposure.Severity's numeric values (Negligible=1 ...
// Critical=5), which would silently change the formula.
func cveSeverityPoints(severity string) float64 {
	switch vulnexposure.ParseSeverity(severity) {
	case vulnexposure.SeverityCritical:
		return 4
	case vulnexposure.SeverityHigh:
		return 3
	case vulnexposure.SeverityMedium:
		return 2
	case vulnexposure.SeverityLow:
		return 1
	default:
		return 0
	}
}
