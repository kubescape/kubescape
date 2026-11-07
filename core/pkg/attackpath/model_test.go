package attackpath

import (
	"reflect"
	"testing"
)

func TestWorkloadNodeID_IncludesKind(t *testing.T) {
	deploy := workloadNodeID(WorkloadRef{Namespace: "prod", Kind: "Deployment", Name: "app"})
	job := workloadNodeID(WorkloadRef{Namespace: "prod", Kind: "Job", Name: "app"})
	if deploy == job {
		t.Fatalf("a Deployment and a Job named alike must be different nodes, both are %q", deploy)
	}
	if want := NodeID("Workload:prod/Deployment/app"); deploy != want {
		t.Errorf("workload ID = %q, want %q", deploy, want)
	}
}

func TestAddEdge_MergesParallelEdgesOfTheSameCertainty(t *testing.T) {
	forward, backward := newGraph(), newGraph()
	a := Edge{From: "x", To: "y", Kind: EdgeExposes, Evidence: "Ingress a/one", Certain: true}
	b := Edge{From: "x", To: "y", Kind: EdgeExposes, Evidence: "Ingress a/two", Certain: true}
	forward.addEdge(a)
	forward.addEdge(b)
	backward.addEdge(b)
	backward.addEdge(a)
	if len(forward.Edges["x"]) != 1 {
		t.Fatalf("expected parallel edges to merge, got %d edges", len(forward.Edges["x"]))
	}
	if !reflect.DeepEqual(forward.Edges, backward.Edges) {
		t.Errorf("merged evidence depends on insertion order: %+v vs %+v", forward.Edges, backward.Edges)
	}
}

func TestAddEdge_KeepsCertainAndUncertainEdgesApart(t *testing.T) {
	g := newGraph()
	g.addEdge(Edge{From: "x", To: "y", Kind: EdgeExposes, Certain: true})
	g.addEdge(Edge{From: "x", To: "y", Kind: EdgeExposes, Certain: false})
	g.addEdge(Edge{From: "x", To: "y", Kind: EdgeNetworkReach, Certain: true})
	if len(g.Edges["x"]) != 3 {
		t.Errorf("expected 3 distinct edges, got %d", len(g.Edges["x"]))
	}
}

func TestFinalize_SortsAndDeduplicatesDiagnostics(t *testing.T) {
	g := newGraph()
	g.warn("b")
	g.warn("a")
	g.warn("b")
	g.skip("z")
	g.skip("z")
	g.finalize()
	if !reflect.DeepEqual(g.Warnings, []string{"a", "b"}) || !reflect.DeepEqual(g.Skipped, []string{"z"}) {
		t.Errorf("warnings=%v skipped=%v", g.Warnings, g.Skipped)
	}
}
