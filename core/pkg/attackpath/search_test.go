package attackpath

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

var (
	fxInternet = nodeID(NodeInternet, "", "")
	fxAdmin    = nodeID(NodeClusterAdmin, "", "cluster-admin")
)

func fxNodeKind(id NodeID) NodeKind {
	switch {
	case id == fxInternet:
		return NodeInternet
	case id == fxAdmin:
		return NodeClusterAdmin
	default:
		return NodeWorkload
	}
}

// fxGraph builds a graph from edges, creating a node for every endpoint.
func fxGraph(edges ...Edge) *Graph {
	g := newGraph()
	for _, e := range edges {
		for _, id := range []NodeID{e.From, e.To} {
			if _, ok := g.Nodes[id]; !ok {
				g.addNode(Node{ID: id, Kind: fxNodeKind(id)})
			}
		}
		g.addEdge(e)
	}
	return g
}

func fxPathIDs(p AttackPath) []NodeID {
	ids := make([]NodeID, len(p.Nodes))
	for i, n := range p.Nodes {
		ids[i] = n.ID
	}
	return ids
}

func TestFindPaths_SimpleChain(t *testing.T) {
	g := fxGraph(
		fxCert(fxInternet, "svc", EdgeExposes),
		fxCert("svc", "wl", EdgeNetworkReach),
		fxCert("wl", "sa", EdgeRunsAs),
		fxCert("sa", fxAdmin, EdgeEscalates),
	)
	r := FindPaths(g, SearchOptions{})
	if len(r.Paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(r.Paths))
	}
	want := []NodeID{fxInternet, "svc", "wl", "sa", fxAdmin}
	if got := fxPathIDs(r.Paths[0]); !reflect.DeepEqual(got, want) {
		t.Errorf("path = %v, want %v", got, want)
	}
	if !r.Paths[0].Certain || r.Truncated || r.DepthLimited || r.Incomplete {
		t.Errorf("unexpected flags: %+v", r)
	}
}

func TestFindPaths_NoPathStillReportsUncertaintyAndDiagnostics(t *testing.T) {
	// The only edge out of the Internet is uncertain and leads nowhere. A
	// negative result must still say so (proposal §7.1).
	g := fxGraph(
		fxUncert(fxInternet, "svc", EdgeExposes),
		fxCert("other", fxAdmin, EdgeEscalates),
	)
	g.Warnings = []string{"RBAC evaluation unavailable"}
	g.Skipped = []string{"Pod kube-system/etcd: static mirror Pod"}
	r := FindPaths(g, SearchOptions{})
	if len(r.Paths) != 0 {
		t.Fatalf("expected no paths, got %d", len(r.Paths))
	}
	if r.UncertainEdgeCount != 1 {
		t.Errorf("UncertainEdgeCount = %d, want 1 (edge is reachable but on no complete path)", r.UncertainEdgeCount)
	}
	if !r.Incomplete || !slices.Equal(r.Warnings, g.Warnings) || !slices.Equal(r.Skipped, g.Skipped) {
		t.Errorf("diagnostics not carried into the result: %+v", r)
	}
}

func TestFindPaths_MissingSourceStillCarriesDiagnostics(t *testing.T) {
	g := fxGraph(fxCert("a", "b", EdgeRunsAs))
	g.Warnings = []string{"exposure analysis unavailable"}
	r := FindPaths(g, SearchOptions{From: "Workload:nope/Deployment/nope"})
	if len(r.Paths) != 0 || !r.Incomplete || len(r.Warnings) != 1 {
		t.Errorf("unexpected result for a missing source: %+v", r)
	}
}

func TestFindPaths_CycleSafe(t *testing.T) {
	g := fxGraph(
		fxCert(fxInternet, "a", EdgeExposes),
		fxCert("a", "b", EdgeNetworkReach),
		fxCert("b", "a", EdgeNetworkReach), // cycle
		fxCert("b", fxAdmin, EdgeEscalates),
	)
	r := FindPaths(g, SearchOptions{})
	if len(r.Paths) != 1 {
		t.Fatalf("expected exactly 1 simple path, got %d", len(r.Paths))
	}
}

func TestFindPaths_DepthCap(t *testing.T) {
	g := fxGraph(
		fxCert(fxInternet, "a", EdgeExposes),
		fxCert("a", "b", EdgeNetworkReach),
		fxCert("b", fxAdmin, EdgeEscalates),
	)
	r := FindPaths(g, SearchOptions{MaxDepth: 2})
	if len(r.Paths) != 0 || !r.DepthLimited {
		t.Errorf("MaxDepth=2: want no paths and DepthLimited, got paths=%d depthLimited=%v", len(r.Paths), r.DepthLimited)
	}
	r = FindPaths(g, SearchOptions{MaxDepth: 3})
	if len(r.Paths) != 1 || r.DepthLimited {
		t.Errorf("MaxDepth=3: want 1 path and not DepthLimited, got paths=%d depthLimited=%v", len(r.Paths), r.DepthLimited)
	}
}

func TestFindPaths_ExactlyMaxPathsIsNotTruncated(t *testing.T) {
	g := fxGraph(
		fxCert(fxInternet, "a", EdgeExposes),
		fxCert("a", fxAdmin, EdgeEscalates),
	)
	r := FindPaths(g, SearchOptions{MaxPaths: 1})
	if len(r.Paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(r.Paths))
	}
	if r.Truncated {
		t.Error("a search that finds exactly MaxPaths paths and no more is complete, not truncated")
	}
}

func TestFindPaths_MoreThanMaxPathsIsTruncated(t *testing.T) {
	g := fxGraph(
		fxCert(fxInternet, "a", EdgeExposes),
		fxCert(fxInternet, "b", EdgeExposes),
		fxCert("a", fxAdmin, EdgeEscalates),
		fxCert("b", fxAdmin, EdgeEscalates),
	)
	r := FindPaths(g, SearchOptions{MaxPaths: 1})
	if len(r.Paths) != 1 || !r.Truncated {
		t.Errorf("want 1 path and Truncated, got paths=%d truncated=%v", len(r.Paths), r.Truncated)
	}
}

func TestFindPaths_SortedByScoreThenStable(t *testing.T) {
	build := func(reverse bool) SearchResult {
		edges := []Edge{
			fxCert(fxInternet, "certain-a", EdgeExposes),
			fxCert("certain-a", fxAdmin, EdgeEscalates),
			fxCert(fxInternet, "certain-b", EdgeExposes),
			fxCert("certain-b", fxAdmin, EdgeEscalates),
			fxUncert(fxInternet, "uncertain", EdgeExposes),
			fxCert("uncertain", fxAdmin, EdgeEscalates),
		}
		if reverse {
			slices.Reverse(edges)
		}
		return FindPaths(fxGraph(edges...), SearchOptions{})
	}
	forward, backward := build(false), build(true)
	if len(forward.Paths) != 3 {
		t.Fatalf("expected 3 paths, got %d", len(forward.Paths))
	}
	if !forward.Paths[0].Certain || !forward.Paths[1].Certain || forward.Paths[2].Certain {
		t.Errorf("certain paths must rank above the uncertain one: %v", []bool{forward.Paths[0].Certain, forward.Paths[1].Certain, forward.Paths[2].Certain})
	}
	// Equal scores are ordered by path identity, independent of insertion order.
	if got, want := fxPathIDs(forward.Paths[0])[1], NodeID("certain-a"); got != want {
		t.Errorf("first tie-break = %v, want %v", got, want)
	}
	if !reflect.DeepEqual(forward.Paths, backward.Paths) {
		t.Error("result depends on edge insertion order")
	}
}

func TestFindPaths_CustomSource(t *testing.T) {
	g := fxGraph(
		fxCert("wl", "sa", EdgeRunsAs),
		fxCert("sa", fxAdmin, EdgeEscalates),
	)
	r := FindPaths(g, SearchOptions{From: "wl"})
	if len(r.Paths) != 1 {
		t.Fatalf("expected 1 path from a custom source, got %d", len(r.Paths))
	}
}

func TestFindPaths_PathCertaintyAndCVEFactorsComeFromWorkloadNodes(t *testing.T) {
	g := fxGraph(
		fxCert(fxInternet, "wl", EdgeExposes),
		fxCert("wl", fxAdmin, EdgeEscalates),
	)
	plain := FindPaths(g, SearchOptions{}).Paths[0]

	wl := g.Nodes["wl"]
	wl.Vulnerabilities = []Vulnerability{
		{ID: "CVE-2", Severity: "High", FixAvailable: false},
		{ID: "CVE-1", Severity: "Critical", FixAvailable: true},
	}
	g.addNode(wl)
	withCVE := FindPaths(g, SearchOptions{}).Paths[0]

	if withCVE.CVESeverity != "Critical" || !withCVE.CVEFixAvailable {
		t.Errorf("CVE factors not derived from the workload node: %+v", withCVE)
	}
	if withCVE.Score <= plain.Score {
		t.Errorf("a Critical fixable CVE on a traversed workload must raise the default path score: %v vs %v", withCVE.Score, plain.Score)
	}
}

func TestFindPaths_PathKeyDoesNotCollideAcrossEvidence(t *testing.T) {
	// Parallel edges of different certainty are different paths.
	g := fxGraph(
		fxCert(fxInternet, "svc", EdgeExposes),
		fxUncert(fxInternet, "svc", EdgeExposes),
		fxCert("svc", fxAdmin, EdgeEscalates),
	)
	r := FindPaths(g, SearchOptions{})
	if len(r.Paths) != 2 {
		t.Fatalf("expected 2 paths over parallel edges, got %d", len(r.Paths))
	}
	if !r.Paths[0].Certain || r.Paths[1].Certain {
		t.Error("certain path must be first")
	}
	if strings.Compare(pathKey(r.Paths[0]), pathKey(r.Paths[1])) == 0 {
		t.Error("distinct paths must have distinct keys")
	}
}
