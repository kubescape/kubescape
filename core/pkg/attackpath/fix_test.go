package attackpath

import "testing"

func TestSuggestFix_EmptyResultReturnsZero(t *testing.T) {
	fix := SuggestFix(SearchResult{})
	if fix.PathsBlocked != 0 || fix.Node.ID != "" {
		t.Errorf("expected zero FixSuggestion for empty result, got %+v", fix)
	}
}

func TestSuggestFix_ReturnsNodeOnMostPaths(t *testing.T) {
	// Build two paths that share a Service node.
	internet := Node{ID: nodeID(NodeInternet, "", ""), Kind: NodeInternet}
	ca := Node{ID: nodeID(NodeClusterAdmin, "", "cluster-admin"), Kind: NodeClusterAdmin, Name: "cluster-admin"}
	svc := Node{ID: nodeID(NodeService, "prod", "web"), Kind: NodeService, Namespace: "prod", Name: "web"}
	wl1 := Node{ID: nodeID(NodeWorkload, "prod", "api"), Kind: NodeWorkload, Namespace: "prod", Name: "api"}
	wl2 := Node{ID: nodeID(NodeWorkload, "prod", "worker"), Kind: NodeWorkload, Namespace: "prod", Name: "worker"}

	path1 := AttackPath{Nodes: []Node{internet, svc, wl1, ca}}
	path2 := AttackPath{Nodes: []Node{internet, svc, wl2, ca}}
	result := SearchResult{Paths: []AttackPath{path1, path2}}

	fix := SuggestFix(result)

	// The Service node appears on both paths; workloads appear on only one.
	if fix.Node.ID != svc.ID {
		t.Errorf("expected Service node as best fix, got %s", fix.Node.ID)
	}
	if fix.PathsBlocked != 2 {
		t.Errorf("expected PathsBlocked=2, got %d", fix.PathsBlocked)
	}
}

func TestSuggestFix_InternetAndClusterAdminExcluded(t *testing.T) {
	// Internet and ClusterAdmin appear on every path but must not be suggested.
	internet := Node{ID: nodeID(NodeInternet, "", ""), Kind: NodeInternet}
	ca := Node{ID: nodeID(NodeClusterAdmin, "", "cluster-admin"), Kind: NodeClusterAdmin, Name: "cluster-admin"}
	svc := Node{ID: nodeID(NodeService, "prod", "web"), Kind: NodeService, Namespace: "prod", Name: "web"}

	result := SearchResult{Paths: []AttackPath{
		{Nodes: []Node{internet, svc, ca}},
	}}
	fix := SuggestFix(result)

	if fix.Node.Kind == NodeInternet || fix.Node.Kind == NodeClusterAdmin {
		t.Errorf("Internet and ClusterAdmin must not be suggested as fixes, got %s", fix.Node.Kind)
	}
}

func TestSuggestFix_TieBrokenByNodeID(t *testing.T) {
	// Two nodes each appear on exactly one path — tie broken by NodeID.
	internet := Node{ID: nodeID(NodeInternet, "", ""), Kind: NodeInternet}
	ca := Node{ID: nodeID(NodeClusterAdmin, "", "cluster-admin"), Kind: NodeClusterAdmin, Name: "cluster-admin"}
	svcA := Node{ID: nodeID(NodeService, "prod", "aaa"), Kind: NodeService, Namespace: "prod", Name: "aaa"}
	svcB := Node{ID: nodeID(NodeService, "prod", "zzz"), Kind: NodeService, Namespace: "prod", Name: "zzz"}

	result := SearchResult{Paths: []AttackPath{
		{Nodes: []Node{internet, svcA, ca}},
		{Nodes: []Node{internet, svcB, ca}},
	}}
	fix := SuggestFix(result)

	// svcA has lexicographically smaller ID than svcB.
	if fix.Node.ID != svcA.ID {
		t.Errorf("expected svcA (lex smaller) to win tie, got %s", fix.Node.ID)
	}
}

func TestSuggestFix_FingerprintsAreSorted(t *testing.T) {
	internet := Node{ID: nodeID(NodeInternet, "", ""), Kind: NodeInternet}
	ca := Node{ID: nodeID(NodeClusterAdmin, "", "cluster-admin"), Kind: NodeClusterAdmin, Name: "cluster-admin"}
	svc := Node{ID: nodeID(NodeService, "prod", "web"), Kind: NodeService, Namespace: "prod", Name: "web"}
	wl1 := Node{ID: nodeID(NodeWorkload, "prod", "api"), Kind: NodeWorkload, Namespace: "prod", Name: "api"}
	wl2 := Node{ID: nodeID(NodeWorkload, "prod", "worker"), Kind: NodeWorkload, Namespace: "prod", Name: "worker"}

	result := SearchResult{Paths: []AttackPath{
		{Nodes: []Node{internet, svc, wl1, ca}},
		{Nodes: []Node{internet, svc, wl2, ca}},
	}}
	fix := SuggestFix(result)

	for i := 1; i < len(fix.FingerprintsBlocked); i++ {
		if fix.FingerprintsBlocked[i] < fix.FingerprintsBlocked[i-1] {
			t.Error("FingerprintsBlocked must be sorted")
		}
	}
}

func TestTopFixes_ReturnsUpToN(t *testing.T) {
	internet := Node{ID: nodeID(NodeInternet, "", ""), Kind: NodeInternet}
	ca := Node{ID: nodeID(NodeClusterAdmin, "", "cluster-admin"), Kind: NodeClusterAdmin, Name: "cluster-admin"}
	svc := Node{ID: nodeID(NodeService, "prod", "web"), Kind: NodeService, Namespace: "prod", Name: "web"}
	wl := Node{ID: nodeID(NodeWorkload, "prod", "api"), Kind: NodeWorkload, Namespace: "prod", Name: "api"}

	result := SearchResult{Paths: []AttackPath{
		{Nodes: []Node{internet, svc, wl, ca}},
	}}

	fixes := TopFixes(result, 5)
	// Only 2 actionable nodes (svc and wl), so at most 2 results.
	if len(fixes) > 2 {
		t.Errorf("expected at most 2 fixes, got %d", len(fixes))
	}
}

func TestTopFixes_EmptyResultReturnsNil(t *testing.T) {
	if fixes := TopFixes(SearchResult{}, 3); fixes != nil {
		t.Errorf("expected nil for empty result, got %+v", fixes)
	}
}

func TestTopFixes_RankedByPathsBlockedDescending(t *testing.T) {
	internet := Node{ID: nodeID(NodeInternet, "", ""), Kind: NodeInternet}
	ca := Node{ID: nodeID(NodeClusterAdmin, "", "cluster-admin"), Kind: NodeClusterAdmin, Name: "cluster-admin"}
	svc := Node{ID: nodeID(NodeService, "prod", "web"), Kind: NodeService, Namespace: "prod", Name: "web"}
	wl1 := Node{ID: nodeID(NodeWorkload, "prod", "a"), Kind: NodeWorkload, Namespace: "prod", Name: "a"}
	wl2 := Node{ID: nodeID(NodeWorkload, "prod", "b"), Kind: NodeWorkload, Namespace: "prod", Name: "b"}

	// svc appears on 2 paths; wl1 and wl2 appear on 1 each.
	result := SearchResult{Paths: []AttackPath{
		{Nodes: []Node{internet, svc, wl1, ca}},
		{Nodes: []Node{internet, svc, wl2, ca}},
	}}

	fixes := TopFixes(result, 3)
	if len(fixes) == 0 {
		t.Fatal("expected at least one fix")
	}
	if fixes[0].Node.ID != svc.ID {
		t.Errorf("expected svc (2 paths) to be first, got %s", fixes[0].Node.ID)
	}
	for i := 1; i < len(fixes); i++ {
		if fixes[i].PathsBlocked > fixes[i-1].PathsBlocked {
			t.Error("TopFixes must be ranked by PathsBlocked descending")
		}
	}
}
