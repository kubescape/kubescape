package attackpath

import (
	"os"
	"path/filepath"
	"testing"
)

func scannedResult(ctx string, paths []AttackPath) ClusterPathResult {
	result := SearchResult{Paths: paths}
	return ClusterPathResult{
		Context:      ctx,
		Status:       "scanned",
		Result:       result,
		Fingerprints: FingerprintResult(result),
	}
}

func errorResult(ctx, errMsg string) ClusterPathResult {
	return ClusterPathResult{
		Context: ctx,
		Status:  "error",
		Error:   errMsg,
	}
}

func simplePathWith(nodeKind NodeKind, ns, name string) AttackPath {
	internet := Node{ID: nodeID(NodeInternet, "", ""), Kind: NodeInternet}
	ca := Node{ID: nodeID(NodeClusterAdmin, "", "cluster-admin"), Kind: NodeClusterAdmin, Name: "cluster-admin"}
	mid := Node{ID: nodeID(nodeKind, ns, name), Kind: nodeKind, Namespace: ns, Name: name}
	return AttackPath{
		Nodes: []Node{internet, mid, ca},
		Edges: []Edge{
			{From: internet.ID, To: mid.ID, Kind: EdgeExposes, Evidence: "Ingress", Certain: true},
			{From: mid.ID, To: ca.ID, Kind: EdgeEscalates, Evidence: "bind-verb", Certain: true},
		},
		Score:   8.0,
		Certain: true,
	}
}

func TestRollupFleetPaths_EmptyReturnsEmptyReport(t *testing.T) {
	report := RollupFleetPaths(nil, nil)
	if len(report.Clusters) != 0 {
		t.Errorf("expected no clusters, got %d", len(report.Clusters))
	}
	if len(report.SharedPaths) != 0 {
		t.Errorf("expected no shared paths, got %d", len(report.SharedPaths))
	}
}

func TestRollupFleetPaths_ErrorClusterKeptInReport(t *testing.T) {
	// A cluster that could not be scanned must appear in the report
	// so the operator sees the gap rather than a silently complete picture.
	results := []ClusterPathResult{
		scannedResult("prod", nil),
		errorResult("staging", "connection refused"),
	}
	report := RollupFleetPaths([]string{"prod", "staging"}, results)

	if len(report.Clusters) != 2 {
		t.Errorf("expected 2 clusters in report, got %d", len(report.Clusters))
	}
	found := false
	for _, cr := range report.Clusters {
		if cr.Context == "staging" && cr.Status == "error" {
			found = true
		}
	}
	if !found {
		t.Error("expected staging error cluster to be present in report")
	}
}

func TestRollupFleetPaths_SharedPathAppearsInEveryScannedCluster(t *testing.T) {
	// Same path in both clusters → SharedPaths.
	sharedPath := simplePathWith(NodeService, "prod", "web")
	results := []ClusterPathResult{
		scannedResult("cluster-a", []AttackPath{sharedPath}),
		scannedResult("cluster-b", []AttackPath{sharedPath}),
	}
	report := RollupFleetPaths([]string{"cluster-a", "cluster-b"}, results)

	if len(report.SharedPaths) != 1 {
		t.Errorf("expected 1 shared path, got %d", len(report.SharedPaths))
	}
	if len(report.UniquePaths) != 0 {
		t.Errorf("expected no unique paths, got %d", len(report.UniquePaths))
	}
}

func TestRollupFleetPaths_UniquePathAppearsInOneClusterOnly(t *testing.T) {
	pathA := simplePathWith(NodeService, "prod", "web-a")
	pathB := simplePathWith(NodeService, "prod", "web-b")
	results := []ClusterPathResult{
		scannedResult("cluster-a", []AttackPath{pathA}),
		scannedResult("cluster-b", []AttackPath{pathB}),
	}
	report := RollupFleetPaths([]string{"cluster-a", "cluster-b"}, results)

	if len(report.SharedPaths) != 0 {
		t.Errorf("expected no shared paths, got %d", len(report.SharedPaths))
	}
	if len(report.UniquePaths) != 2 {
		t.Errorf("expected 2 unique paths, got %d", len(report.UniquePaths))
	}
}

func TestRollupFleetPaths_TruncatedWhenAnyClusterTruncated(t *testing.T) {
	cr := scannedResult("prod", nil)
	cr.Result.Truncated = true
	report := RollupFleetPaths([]string{"prod"}, []ClusterPathResult{cr})
	if !report.Truncated {
		t.Error("expected Truncated=true when any cluster result is truncated")
	}
}

func TestRollupFleetPaths_TotalPathsCountsAcrossClusters(t *testing.T) {
	p1 := simplePathWith(NodeService, "prod", "a")
	p2 := simplePathWith(NodeService, "prod", "b")
	results := []ClusterPathResult{
		scannedResult("cluster-a", []AttackPath{p1}),
		scannedResult("cluster-b", []AttackPath{p2}),
	}
	report := RollupFleetPaths([]string{"cluster-a", "cluster-b"}, results)
	if report.TotalPathsAcrossClusters != 2 {
		t.Errorf("expected TotalPathsAcrossClusters=2, got %d", report.TotalPathsAcrossClusters)
	}
}

func TestRollupFleetPaths_OutputIsDeterministic(t *testing.T) {
	p := simplePathWith(NodeService, "prod", "web")
	results := []ClusterPathResult{
		scannedResult("zzz", []AttackPath{p}),
		scannedResult("aaa", []AttackPath{p}),
	}
	r1 := RollupFleetPaths([]string{"zzz", "aaa"}, results)
	r2 := RollupFleetPaths([]string{"zzz", "aaa"}, results)

	if len(r1.Clusters) != len(r2.Clusters) {
		t.Fatalf("cluster count differs: %d vs %d", len(r1.Clusters), len(r2.Clusters))
	}
	for i := range r1.Clusters {
		if r1.Clusters[i].Context != r2.Clusters[i].Context {
			t.Errorf("cluster order differs at %d: %s vs %s",
				i, r1.Clusters[i].Context, r2.Clusters[i].Context)
		}
	}
	// Clusters must be sorted by context.
	if r1.Clusters[0].Context != "aaa" {
		t.Errorf("expected aaa first after sort, got %s", r1.Clusters[0].Context)
	}
}

func TestWriteFleetPathReport_WritesAndReadsBack(t *testing.T) {
	p := simplePathWith(NodeService, "prod", "web")
	results := []ClusterPathResult{scannedResult("prod", []AttackPath{p})}
	report := RollupFleetPaths([]string{"prod"}, results)

	dir := t.TempDir()
	path := filepath.Join(dir, "fleet-paths.json")
	if err := WriteFleetPathReport(path, report); err != nil {
		t.Fatalf("WriteFleetPathReport error: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected file to exist after write: %v", err)
	}
}
