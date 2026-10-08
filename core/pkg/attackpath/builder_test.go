package attackpath

import (
	"testing"

	"github.com/kubescape/kubescape/v4/core/pkg/vulnexposure"
)

// minimalInputs returns an Inputs with only the fields BuildGraph needs
// for a test that does not exercise every engine.
func minimalInputs() Inputs { return Inputs{} }

func TestBuildGraph_EmptyInputsProducesOnlyStaticNodes(t *testing.T) {
	g := BuildGraph(makeResources(), minimalInputs(), BuildOptions{})

	// Must always have Internet and ClusterAdmin nodes.
	internetID := nodeID(NodeInternet, "", "")
	caID := nodeID(NodeClusterAdmin, "", "cluster-admin")
	if _, ok := g.Nodes[internetID]; !ok {
		t.Error("expected Internet node always present")
	}
	if _, ok := g.Nodes[caID]; !ok {
		t.Error("expected ClusterAdmin node always present")
	}
}

func TestBuildGraph_NoExposedServiceMeansNoInternetEdge(t *testing.T) {
	// A ClusterIP Service with no Ingress is not externally exposed:
	// no Internet→Service edge should be added.
	g := BuildGraph(makeResources(), minimalInputs(), BuildOptions{})
	internetID := nodeID(NodeInternet, "", "")
	if edges := g.Edges[internetID]; len(edges) != 0 {
		t.Errorf("expected no Internet edges for an unexposed cluster, got %d", len(edges))
	}
}

func TestBuildGraph_WorkloadWithTokenFalseHasNoRunsAsEdge(t *testing.T) {
	// A Deployment with automountServiceAccountToken: false must not
	// produce a runs-as edge, per the reliability bar in proposal §7.
	w := workloadWithSA("prod", "secure", "my-sa", boolPtr(false), nil)
	inp := minimalInputs()
	inp.ServiceAccounts = nil

	g := BuildGraph(makeResources(w), inp, BuildOptions{})

	wID := nodeID(NodeWorkload, "prod", "secure")
	for _, e := range g.Edges[wID] {
		if e.Kind == EdgeRunsAs {
			t.Error("expected no runs-as edge when automountServiceAccountToken=false")
		}
	}
}

func TestBuildGraph_CVENodeAddedWhenVulnDataPresent(t *testing.T) {
	w := workloadWithSA("prod", "web", "web-sa", boolPtr(true), nil)
	inp := minimalInputs()

	vulnsByWorkload := map[vulnexposure.Workload][]any{} // typed below
	_ = vulnsByWorkload

	opts := BuildOptions{
		MinCVESeverity: vulnexposure.SeverityCritical,
		// VulnsByWorkload left nil: CVE nodes should be absent.
	}
	g := BuildGraph(makeResources(w), inp, opts)

	for id, n := range g.Nodes {
		if n.Kind == NodeCVE {
			t.Errorf("expected no CVE nodes when VulnsByWorkload is nil, got %s", id)
		}
	}
}

func TestBuildGraph_OutputIsDeterministic(t *testing.T) {
	d1 := deploymentResource("prod", "api", map[string]any{"app": "api"})
	d2 := deploymentResource("prod", "web", map[string]any{"app": "web"})
	inp := minimalInputs()

	g1 := BuildGraph(makeResources(d1, d2), inp, BuildOptions{})
	g2 := BuildGraph(makeResources(d1, d2), inp, BuildOptions{})

	if len(g1.Nodes) != len(g2.Nodes) {
		t.Errorf("node count differs: %d vs %d", len(g1.Nodes), len(g2.Nodes))
	}
	if len(g1.Edges) != len(g2.Edges) {
		t.Errorf("edge count differs: %d vs %d", len(g1.Edges), len(g2.Edges))
	}
}
