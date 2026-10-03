package attackpath

import "testing"

func TestFingerprintPath_SamePathSameFingerprint(t *testing.T) {
	g := linearGraph()
	opts := SearchOptions{}
	r1 := FindPaths(g, opts)
	r2 := FindPaths(g, opts)

	if len(r1.Paths) == 0 {
		t.Skip("no paths found")
	}
	fp1 := FingerprintPath(r1.Paths[0])
	fp2 := FingerprintPath(r2.Paths[0])
	if fp1 != fp2 {
		t.Errorf("same path produced different fingerprints: %s vs %s", fp1, fp2)
	}
}

func TestFingerprintPath_DifferentPathsDifferentFingerprints(t *testing.T) {
	// Two paths with different node sets must have different fingerprints.
	internet := Node{ID: nodeID(NodeInternet, "", ""), Kind: NodeInternet}
	ca := Node{ID: nodeID(NodeClusterAdmin, "", "cluster-admin"), Kind: NodeClusterAdmin, Name: "cluster-admin"}
	svc := Node{ID: nodeID(NodeService, "prod", "web"), Kind: NodeService, Namespace: "prod", Name: "web"}

	p1 := AttackPath{Nodes: []Node{internet, ca}}
	p2 := AttackPath{Nodes: []Node{internet, svc, ca}}

	if FingerprintPath(p1) == FingerprintPath(p2) {
		t.Error("paths with different node sets must have different fingerprints")
	}
}

func TestFingerprintPath_OrderIndependent(t *testing.T) {
	// Node order in the slice must not affect the fingerprint.
	internet := Node{ID: nodeID(NodeInternet, "", ""), Kind: NodeInternet}
	ca := Node{ID: nodeID(NodeClusterAdmin, "", "cluster-admin"), Kind: NodeClusterAdmin, Name: "cluster-admin"}

	p1 := AttackPath{Nodes: []Node{internet, ca}}
	p2 := AttackPath{Nodes: []Node{ca, internet}} // reversed

	if FingerprintPath(p1) != FingerprintPath(p2) {
		t.Error("fingerprint must be order-independent across node slice order")
	}
}

func TestFingerprintPath_NonEmptyString(t *testing.T) {
	p := AttackPath{Nodes: []Node{
		{ID: nodeID(NodeInternet, "", ""), Kind: NodeInternet},
	}}
	fp := FingerprintPath(p)
	if fp == "" {
		t.Error("expected non-empty fingerprint")
	}
	if len(fp) != 16 {
		t.Errorf("expected 16 hex chars, got %d: %s", len(fp), fp)
	}
}

func TestFingerprintResult_LengthMatchesPaths(t *testing.T) {
	g := linearGraph()
	result := FindPaths(g, SearchOptions{})
	fps := FingerprintResult(result)
	if len(fps) != len(result.Paths) {
		t.Errorf("FingerprintResult length %d != paths length %d", len(fps), len(result.Paths))
	}
}
