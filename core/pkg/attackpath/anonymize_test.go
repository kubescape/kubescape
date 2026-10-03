package attackpath

import "testing"

func twoNodePath(fromKind, toKind NodeKind, fromNS, fromName, toNS, toName string) AttackPath {
	from := Node{
		ID:        nodeID(fromKind, fromNS, fromName),
		Kind:      fromKind,
		Namespace: fromNS,
		Name:      fromName,
	}
	to := Node{
		ID:        nodeID(toKind, toNS, toName),
		Kind:      toKind,
		Namespace: toNS,
		Name:      toName,
	}
	return AttackPath{
		Nodes: []Node{from, to},
		Edges: []Edge{{
			From:     from.ID,
			To:       to.ID,
			Kind:     EdgeRunsAs,
			Evidence: "serviceAccountName=" + toName,
			Certain:  true,
		}},
		Score:   7.0,
		Certain: true,
	}
}

func TestAnonymizer_WorkloadNameIsReplaced(t *testing.T) {
	a := NewAnonymizer("test-salt")
	p := twoNodePath(NodeWorkload, NodeServiceAccount, "prod", "web", "prod", "web-sa")
	anon := a.AnonymizePath(p)

	for _, n := range anon.Nodes {
		if n.Kind == NodeWorkload && n.Name == "web" {
			t.Error("expected workload name 'web' to be anonymized")
		}
		if n.Kind == NodeServiceAccount && n.Name == "web-sa" {
			t.Error("expected SA name 'web-sa' to be anonymized")
		}
	}
}

func TestAnonymizer_NamespaceIsReplaced(t *testing.T) {
	a := NewAnonymizer("test-salt")
	p := twoNodePath(NodeWorkload, NodeServiceAccount, "prod", "web", "prod", "web-sa")
	anon := a.AnonymizePath(p)

	for _, n := range anon.Nodes {
		if n.Namespace == "prod" {
			t.Errorf("expected namespace 'prod' to be anonymized, got %q for kind %s", n.Namespace, n.Kind)
		}
	}
}

func TestAnonymizer_InternetNodeIsPreserved(t *testing.T) {
	a := NewAnonymizer("test-salt")
	internet := Node{
		ID:   nodeID(NodeInternet, "", ""),
		Kind: NodeInternet,
		Name: "Internet",
	}
	ca := Node{
		ID:   nodeID(NodeClusterAdmin, "", "cluster-admin"),
		Kind: NodeClusterAdmin,
		Name: "cluster-admin",
	}
	p := AttackPath{
		Nodes: []Node{internet, ca},
		Edges: []Edge{{From: internet.ID, To: ca.ID, Kind: EdgeEscalates, Evidence: "bind-verb", Certain: true}},
	}
	anon := a.AnonymizePath(p)

	for _, n := range anon.Nodes {
		if n.Kind == NodeInternet && n.Name != "Internet" {
			t.Errorf("Internet node name should be preserved, got %q", n.Name)
		}
		if n.Kind == NodeClusterAdmin && n.Name != "cluster-admin" {
			t.Errorf("ClusterAdmin node name should be preserved, got %q", n.Name)
		}
	}
}

func TestAnonymizer_PseudonymsAreDeterministic(t *testing.T) {
	// Same salt + same name must always produce the same pseudonym.
	a1 := NewAnonymizer("salt-abc")
	a2 := NewAnonymizer("salt-abc")
	p := twoNodePath(NodeWorkload, NodeServiceAccount, "prod", "web", "prod", "web-sa")

	anon1 := a1.AnonymizePath(p)
	anon2 := a2.AnonymizePath(p)

	for i := range anon1.Nodes {
		if anon1.Nodes[i].Name != anon2.Nodes[i].Name {
			t.Errorf("pseudonyms differ for same salt: %q vs %q",
				anon1.Nodes[i].Name, anon2.Nodes[i].Name)
		}
	}
}

func TestAnonymizer_DifferentSaltsDifferentPseudonyms(t *testing.T) {
	a1 := NewAnonymizer("salt-one")
	a2 := NewAnonymizer("salt-two")
	p := twoNodePath(NodeWorkload, NodeServiceAccount, "prod", "web", "prod", "web-sa")

	anon1 := a1.AnonymizePath(p)
	anon2 := a2.AnonymizePath(p)

	anyDiffer := false
	for i := range anon1.Nodes {
		if anon1.Nodes[i].Name != anon2.Nodes[i].Name {
			anyDiffer = true
		}
	}
	if !anyDiffer {
		t.Error("expected different pseudonyms for different salts")
	}
}

func TestAnonymizer_RunsAsEvidenceIsAnonymized(t *testing.T) {
	a := NewAnonymizer("test-salt")
	p := twoNodePath(NodeWorkload, NodeServiceAccount, "prod", "web", "prod", "web-sa")
	anon := a.AnonymizePath(p)

	for _, e := range anon.Edges {
		if e.Kind == EdgeRunsAs && e.Evidence == "serviceAccountName=web-sa" {
			t.Error("expected runs-as evidence to have SA name anonymized")
		}
	}
}

func TestAnonymizer_CVENodeIsPreserved(t *testing.T) {
	a := NewAnonymizer("test-salt")
	cveNode := Node{
		ID:   nodeID(NodeCVE, "", "CVE-2024-1234"),
		Kind: NodeCVE,
		Name: "CVE-2024-1234",
	}
	wl := Node{
		ID:        nodeID(NodeWorkload, "prod", "web"),
		Kind:      NodeWorkload,
		Namespace: "prod",
		Name:      "web",
	}
	p := AttackPath{
		Nodes: []Node{wl, cveNode},
		Edges: []Edge{{From: wl.ID, To: cveNode.ID, Kind: EdgeVulnerable,
			Evidence: "severity=Critical fix=true", Certain: true}},
	}
	anon := a.AnonymizePath(p)

	for _, n := range anon.Nodes {
		if n.Kind == NodeCVE && n.Name != "CVE-2024-1234" {
			t.Errorf("CVE ID should be preserved, got %q", n.Name)
		}
	}
}

func TestAnonymizer_ScoreAndCertaintyPreserved(t *testing.T) {
	a := NewAnonymizer("test-salt")
	p := twoNodePath(NodeWorkload, NodeServiceAccount, "prod", "web", "prod", "web-sa")
	p.Score = 8.5
	p.Certain = false
	p.CVESeverity = "Critical"

	anon := a.AnonymizePath(p)
	if anon.Score != 8.5 {
		t.Errorf("expected Score 8.5 preserved, got %f", anon.Score)
	}
	if anon.Certain {
		t.Error("expected Certain=false preserved")
	}
	if anon.CVESeverity != "Critical" {
		t.Errorf("expected CVESeverity 'Critical' preserved, got %q", anon.CVESeverity)
	}
}
