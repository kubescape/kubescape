package attackpath

import "testing"

func certEdge(from, to NodeID, kind EdgeKind) Edge {
	return Edge{From: from, To: to, Kind: kind, Evidence: "", Certain: true}
}

func uncertEdge(from, to NodeID, kind EdgeKind) Edge {
	return Edge{From: from, To: to, Kind: kind, Evidence: "", Certain: false}
}

func TestScorePath_ClusterAdminSinkAddsPoints(t *testing.T) {
	withCA := AttackPath{
		Nodes:   []Node{{Kind: NodeInternet}, {Kind: NodeClusterAdmin, Name: "cluster-admin"}},
		Edges:   []Edge{certEdge("a", "b", EdgeEscalates)},
		Certain: true,
	}
	withoutCA := AttackPath{
		Nodes:   []Node{{Kind: NodeInternet}, {Kind: NodeWorkload}},
		Edges:   []Edge{certEdge("a", "b", EdgeNetworkReach)},
		Certain: true,
	}
	if ScorePath(withCA) <= ScorePath(withoutCA) {
		t.Error("path reaching ClusterAdmin must score higher than one that does not")
	}
}

func TestScorePath_CriticalCVEScoresHigherThanNoCVE(t *testing.T) {
	withCVE := AttackPath{
		Nodes:       []Node{{Kind: NodeWorkload}, {Kind: NodeCVE}},
		Edges:       []Edge{certEdge("w", "cve", EdgeVulnerable)},
		CVESeverity: "Critical",
		Certain:     true,
	}
	withoutCVE := AttackPath{
		Nodes:   []Node{{Kind: NodeWorkload}},
		Edges:   []Edge{},
		Certain: true,
	}
	if ScorePath(withCVE) <= ScorePath(withoutCVE) {
		t.Error("path with Critical CVE must score higher than path with no CVE")
	}
}

func TestScorePath_CertainPathScoresHigherThanUncertain(t *testing.T) {
	certain := AttackPath{
		Nodes:   []Node{{Kind: NodeInternet}, {Kind: NodeClusterAdmin, Name: "cluster-admin"}},
		Edges:   []Edge{certEdge("a", "b", EdgeEscalates)},
		Certain: true,
	}
	uncertain := AttackPath{
		Nodes:   []Node{{Kind: NodeInternet}, {Kind: NodeClusterAdmin, Name: "cluster-admin"}},
		Edges:   []Edge{uncertEdge("a", "b", EdgeEscalates)},
		Certain: false,
	}
	if ScorePath(certain) <= ScorePath(uncertain) {
		t.Error("certain path must score higher than otherwise identical uncertain path")
	}
}

func TestScorePath_ShorterPathScoresHigher(t *testing.T) {
	short := AttackPath{
		Nodes:   []Node{{Kind: NodeInternet}, {Kind: NodeClusterAdmin, Name: "cluster-admin"}},
		Edges:   []Edge{certEdge("a", "b", EdgeEscalates), certEdge("b", "c", EdgeEscalates)},
		Certain: true,
	}
	long := AttackPath{
		Nodes: []Node{
			{Kind: NodeInternet}, {Kind: NodeService},
			{Kind: NodeWorkload}, {Kind: NodeServiceAccount},
			{Kind: NodeClusterAdmin, Name: "cluster-admin"},
			{Kind: NodeCVE}, {Kind: NodeCVE},
		},
		Edges: []Edge{
			certEdge("a", "b", EdgeExposes),
			certEdge("b", "c", EdgeNetworkReach),
			certEdge("c", "d", EdgeRunsAs),
			certEdge("d", "e", EdgeEscalates),
			certEdge("e", "f", EdgeVulnerable),
			certEdge("f", "g", EdgeVulnerable),
		},
		Certain: true,
	}
	if ScorePath(short) <= ScorePath(long) {
		t.Error("shorter path must score higher when other factors are equal")
	}
}

func TestScorePath_MaxScoreIsCappedAt10(t *testing.T) {
	// Construct a path that hits every bonus.
	p := AttackPath{
		Nodes: []Node{
			{Kind: NodeInternet},
			{Kind: NodeClusterAdmin, Name: "cluster-admin"},
			{Kind: NodeCVE},
		},
		Edges: []Edge{
			{From: "a", To: "b", Kind: EdgeEscalates, Evidence: "fix=true", Certain: true},
			{From: "b", To: "c", Kind: EdgeVulnerable, Evidence: "severity=Critical fix=true", Certain: true},
		},
		CVESeverity: "Critical",
		Certain:     true,
	}
	if score := ScorePath(p); score > 10 {
		t.Errorf("score must be capped at 10, got %f", score)
	}
}

func TestScorePath_ZeroForEmptyPath(t *testing.T) {
	if score := ScorePath(AttackPath{}); score != 0 {
		t.Errorf("expected score 0 for empty path, got %f", score)
	}
}
