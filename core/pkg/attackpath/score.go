package attackpath

// ScorePath computes a 0–10 risk score for one AttackPath.
// The formula is documented here so it is auditable; the factors are also
// emitted in JSON output (Phase 3) so rankings are not a black box.
//
// Factors (all emitted in JSON in Phase 3):
//   - CVE severity on the path:    Critical=4, High=3, Medium=2, Low=1, none=0
//   - Sink is ClusterAdmin:        +2
//   - Path is fully Certain:       +1
//   - Shorter path (fewer edges):  +1 when ≤ 3 edges, +0.5 when ≤ 5
//   - CVE fix available:           +0.5 (more actionable)
//
// Raw sum is capped at 10.
func ScorePath(p AttackPath) float64 {
	var score float64

	// CVE severity factor.
	score += float64(CVESeverityRank(p.CVESeverity))

	// Sink factor: does this path reach ClusterAdmin?
	for _, n := range p.Nodes {
		if n.Kind == NodeClusterAdmin {
			score += 2
			break
		}
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
	for _, e := range p.Edges {
		if e.Kind == EdgeVulnerable && containsString(e.Evidence, "fix=true") {
			score += 0.5
			break
		}
	}

	if score > 10 {
		score = 10
	}
	return score
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && func() bool {
		for i := 0; i <= len(s)-len(substr); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	}()
}
