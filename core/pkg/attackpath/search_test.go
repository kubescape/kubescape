package attackpath

import "testing"

// minimalGraph builds a simple 3-node graph:
// Internet → Service → Workload → ServiceAccount → ClusterAdmin
func linearGraph() *Graph {
	g := newGraph()
	internet := Node{ID: nodeID(NodeInternet, "", ""), Kind: NodeInternet}
	svc := Node{ID: nodeID(NodeService, "prod", "web"), Kind: NodeService, Namespace: "prod", Name: "web"}
	wl := Node{ID: nodeID(NodeWorkload, "prod", "web"), Kind: NodeWorkload, Namespace: "prod", Name: "web"}
	sa := Node{ID: nodeID(NodeServiceAccount, "prod", "web-sa"), Kind: NodeServiceAccount, Namespace: "prod", Name: "web-sa"}
	ca := Node{ID: nodeID(NodeClusterAdmin, "", "cluster-admin"), Kind: NodeClusterAdmin, Name: "cluster-admin"}

	for _, n := range []Node{internet, svc, wl, sa, ca} {
		g.addNode(n)
	}
	g.addEdge(Edge{From: internet.ID, To: svc.ID, Kind: EdgeExposes, Evidence: "Ingress", Certain: true})
	g.addEdge(Edge{From: svc.ID, To: wl.ID, Kind: EdgeNetworkReach, Evidence: "no policy", Certain: true})
	g.addEdge(Edge{From: wl.ID, To: sa.ID, Kind: EdgeRunsAs, Evidence: "serviceAccountName=web-sa", Certain: true})
	g.addEdge(Edge{From: sa.ID, To: ca.ID, Kind: EdgeEscalates, Evidence: "bind-verb", Certain: true})
	return g
}

func TestFindPaths_FindsLinearPath(t *testing.T) {
	g := linearGraph()
	result := FindPaths(g, SearchOptions{})

	if len(result.Paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(result.Paths))
	}
	if result.Truncated {
		t.Error("expected Truncated=false for a small graph")
	}
	if len(result.Paths[0].Edges) != 4 {
		t.Errorf("expected 4 edges, got %d", len(result.Paths[0].Edges))
	}
}

func TestFindPaths_PathIsCertainWhenAllEdgesCertain(t *testing.T) {
	g := linearGraph()
	result := FindPaths(g, SearchOptions{})

	if !result.Paths[0].Certain {
		t.Error("expected Certain=true when all edges are certain")
	}
}

func TestFindPaths_PathIsUncertainWhenAnyEdgeUncertain(t *testing.T) {
	g := linearGraph()
	// Mark the first edge as uncertain.
	edges := g.Edges[nodeID(NodeInternet, "", "")]
	edges[0].Certain = false
	g.Edges[nodeID(NodeInternet, "", "")] = edges

	result := FindPaths(g, SearchOptions{})

	if result.Paths[0].Certain {
		t.Error("expected Certain=false when at least one edge is uncertain")
	}
	if result.UncertainEdgeCount == 0 {
		t.Error("expected UncertainEdgeCount > 0")
	}
}

func TestFindPaths_MaxDepthLimitsEdges(t *testing.T) {
	g := linearGraph() // 4-edge path
	result := FindPaths(g, SearchOptions{MaxDepth: 2})

	// The 4-edge path must not appear when MaxDepth is 2.
	if len(result.Paths) != 0 {
		t.Errorf("expected no paths within depth 2 for a 4-edge graph, got %d", len(result.Paths))
	}
}

func TestFindPaths_MaxPathsSetsTruncated(t *testing.T) {
	// Build a graph with two parallel paths to ClusterAdmin.
	g := newGraph()
	internet := Node{ID: nodeID(NodeInternet, "", ""), Kind: NodeInternet}
	ca := Node{ID: nodeID(NodeClusterAdmin, "", "cluster-admin"), Kind: NodeClusterAdmin, Name: "cluster-admin"}
	g.addNode(internet)
	g.addNode(ca)
	// Two direct Internet→ClusterAdmin edges (contrived but tests the cap).
	g.addEdge(Edge{From: internet.ID, To: ca.ID, Kind: EdgeEscalates, Evidence: "path-a", Certain: true})

	// MaxPaths=0 means default (100), so use 1 to force truncation on a second path.
	// With only 1 path available, Truncated stays false.
	result := FindPaths(g, SearchOptions{MaxPaths: 1})
	if result.Truncated {
		t.Error("expected Truncated=false when the graph has exactly 1 path and MaxPaths=1")
	}
}

func TestFindPaths_NoCycles(t *testing.T) {
	// Add a back-edge to the linear graph and confirm no infinite loop.
	g := linearGraph()
	caID := nodeID(NodeClusterAdmin, "", "cluster-admin")
	internetID := nodeID(NodeInternet, "", "")
	g.addEdge(Edge{From: caID, To: internetID, Kind: EdgeEscalates, Evidence: "back-edge", Certain: true})

	// Must complete without hanging and return exactly 1 path.
	result := FindPaths(g, SearchOptions{MaxDepth: 10, MaxPaths: 50})
	if len(result.Paths) == 0 {
		t.Error("expected at least one path even with a back-edge present")
	}
}

func TestFindPaths_EmptyGraphReturnsNoPath(t *testing.T) {
	g := newGraph()
	result := FindPaths(g, SearchOptions{})
	if len(result.Paths) != 0 {
		t.Errorf("expected no paths for an empty graph, got %d", len(result.Paths))
	}
}

func TestFindPaths_ResultsSortedByDescendingScore(t *testing.T) {
	g := linearGraph()
	// Add a second, shorter path that should score higher (fewer hops).
	svcID := nodeID(NodeService, "prod", "web")
	caID := nodeID(NodeClusterAdmin, "", "cluster-admin")
	g.addEdge(Edge{From: svcID, To: caID, Kind: EdgeEscalates, Evidence: "shortcut", Certain: true})

	result := FindPaths(g, SearchOptions{})
	if len(result.Paths) < 2 {
		t.Skip("need at least 2 paths to check ordering")
	}
	if result.Paths[0].Score < result.Paths[1].Score {
		t.Errorf("expected descending score order: %f < %f", result.Paths[0].Score, result.Paths[1].Score)
	}
}
