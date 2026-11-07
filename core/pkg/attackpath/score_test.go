package attackpath

import "testing"

func fxCert(from, to NodeID, kind EdgeKind) Edge {
	return Edge{From: from, To: to, Kind: kind, Certain: true}
}

func fxUncert(from, to NodeID, kind EdgeKind) Edge {
	return Edge{From: from, To: to, Kind: kind, Certain: false}
}

func TestScorePath_ClusterAdminSinkAddsPoints(t *testing.T) {
	withCA := AttackPath{
		Nodes:   []Node{{Kind: NodeInternet}, {Kind: NodeClusterAdmin, Name: "cluster-admin"}},
		Edges:   []Edge{fxCert("a", "b", EdgeEscalates)},
		Certain: true,
	}
	withoutCA := AttackPath{
		Nodes:   []Node{{Kind: NodeInternet}, {Kind: NodeWorkload}},
		Edges:   []Edge{fxCert("a", "b", EdgeNetworkReach)},
		Certain: true,
	}
	if ScorePath(withCA) <= ScorePath(withoutCA) {
		t.Error("path reaching ClusterAdmin must score higher than one that does not")
	}
}

func TestScorePath_CriticalCVEScoresHigherThanNoCVE(t *testing.T) {
	base := AttackPath{
		Nodes:   []Node{{Kind: NodeInternet}, {Kind: NodeWorkload}},
		Edges:   []Edge{fxCert("a", "b", EdgeNetworkReach)},
		Certain: true,
	}
	withCVE := base
	withCVE.CVESeverity = "Critical"
	if ScorePath(withCVE) <= ScorePath(base) {
		t.Error("path with Critical CVE must score higher than path with no CVE")
	}
}

// The documented scale is Critical=4, High=3, Medium=2, Low=1. It must not
// follow vulnexposure.Severity's enum values (Negligible=1 ... Critical=5).
func TestScorePath_CVESeverityUsesDocumentedScale(t *testing.T) {
	base := AttackPath{
		Nodes:   []Node{{Kind: NodeInternet}, {Kind: NodeWorkload}},
		Edges:   []Edge{fxCert("a", "b", EdgeNetworkReach)},
		Certain: true,
	}
	score := func(sev string) float64 {
		p := base
		p.CVESeverity = sev
		return ScorePath(p)
	}
	none := score("")
	for sev, want := range map[string]float64{"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Negligible": 0, "Unknown": 0, "garbage": 0} {
		if got := score(sev) - none; got != want {
			t.Errorf("severity %q adds %v points, want %v", sev, got, want)
		}
	}
}

func TestScorePath_FixAvailableNeedsACVE(t *testing.T) {
	base := AttackPath{
		Nodes:   []Node{{Kind: NodeInternet}, {Kind: NodeWorkload}},
		Edges:   []Edge{fxCert("a", "b", EdgeNetworkReach)},
		Certain: true,
	}
	fixNoCVE := base
	fixNoCVE.CVEFixAvailable = true
	if ScorePath(fixNoCVE) != ScorePath(base) {
		t.Error("fix-available bonus must not apply without a CVE")
	}
	withCVE, withFix := base, base
	withCVE.CVESeverity = "High"
	withFix.CVESeverity = "High"
	withFix.CVEFixAvailable = true
	if got := ScorePath(withFix) - ScorePath(withCVE); got != 0.5 {
		t.Errorf("fix-available bonus = %v, want 0.5", got)
	}
}

func TestScorePath_CertainPathScoresHigherThanUncertain(t *testing.T) {
	certain := AttackPath{
		Nodes:   []Node{{Kind: NodeInternet}, {Kind: NodeClusterAdmin, Name: "cluster-admin"}},
		Edges:   []Edge{fxCert("a", "b", EdgeEscalates)},
		Certain: true,
	}
	uncertain := AttackPath{
		Nodes:   []Node{{Kind: NodeInternet}, {Kind: NodeClusterAdmin, Name: "cluster-admin"}},
		Edges:   []Edge{fxUncert("a", "b", EdgeEscalates)},
		Certain: false,
	}
	if ScorePath(certain) <= ScorePath(uncertain) {
		t.Error("certain path must score higher than otherwise identical uncertain path")
	}
}

func TestScorePath_ShorterPathScoresHigher(t *testing.T) {
	edges := func(n int) []Edge {
		out := make([]Edge, n)
		for i := range out {
			out[i] = fxCert("a", "b", EdgeNetworkReach)
		}
		return out
	}
	mk := func(n int) AttackPath {
		return AttackPath{Nodes: []Node{{Kind: NodeInternet}, {Kind: NodeWorkload}}, Edges: edges(n), Certain: true}
	}
	if !(ScorePath(mk(3)) > ScorePath(mk(5)) && ScorePath(mk(5)) > ScorePath(mk(6))) {
		t.Errorf("expected strictly decreasing scores for 3, 5, 6 edges, got %v %v %v",
			ScorePath(mk(3)), ScorePath(mk(5)), ScorePath(mk(6)))
	}
}

func TestScorePath_FullFormula(t *testing.T) {
	// Critical (4) + ClusterAdmin (2) + certain (1) + <=5 edges (0.5) + fix (0.5)
	p := AttackPath{
		Nodes:           []Node{{Kind: NodeInternet}, {Kind: NodeWorkload}, {Kind: NodeClusterAdmin}},
		Edges:           []Edge{fxCert("a", "b", EdgeNetworkReach), fxCert("b", "c", EdgeRunsAs), fxCert("c", "d", EdgeEscalates), fxCert("d", "e", EdgeEscalates)},
		Certain:         true,
		CVESeverity:     "Critical",
		CVEFixAvailable: true,
	}
	if got := ScorePath(p); got != 8 {
		t.Errorf("score = %v, want 8", got)
	}
}

func TestScorePath_NeverExceedsTen(t *testing.T) {
	p := AttackPath{
		Nodes:           []Node{{Kind: NodeInternet}, {Kind: NodeClusterAdmin}},
		Edges:           []Edge{fxCert("a", "b", EdgeEscalates)},
		Certain:         true,
		CVESeverity:     "Critical",
		CVEFixAvailable: true,
	}
	if score := ScorePath(p); score > 10 {
		t.Errorf("score must be capped at 10, got %f", score)
	}
}

func TestScorePath_ZeroForEmptyPath(t *testing.T) {
	if score := ScorePath(AttackPath{}); score != 0 {
		t.Errorf("expected score 0 for empty path, got %f", score)
	}
	// Even a path flagged Certain with a CVE connects nothing if it has no edges.
	if score := ScorePath(AttackPath{Certain: true, CVESeverity: "Critical"}); score != 0 {
		t.Errorf("expected score 0 for an edgeless path, got %f", score)
	}
}
