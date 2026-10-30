package componentvulns

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kubescape/kubescape/v4/core/pkg/clustercomponents"
	"github.com/kubescape/kubescape/v4/core/pkg/k8scveindex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testFeed = `{
  "_kubernetes_io": {"updated_at": "2026-10-01T00:00:00Z"},
  "items": [
    {
      "id": "CVE-2024-3177",
      "summary": "Bypassing mountable secrets policy imposed by the ServiceAccount admission plugin",
      "content_text": "#### Affected Versions\n\n- kube-apiserver v1.29.0 - v1.29.3\n- kube-apiserver v1.28.0 - v1.28.8\n- kube-apiserver <= v1.27.12\n"
    },
    {
      "id": "CVE-2023-3676",
      "summary": "Insufficient input sanitization on Windows nodes leads to privilege escalation",
      "content_text": "#### Affected Versions\n\n- kubelet <= v1.28.0\n- kubelet <= v1.27.4\n"
    }
  ]
}`

type advisory struct {
	id       string
	related  []string
	severity string
	fixedIn  []string
	kev      bool
	epss     float64
}

type fakeMatcher struct {
	advisories map[string][]advisory
	err        error
	calls      int
	packages   []pkg.Package
}

func (f *fakeMatcher) MatchPackages(packages []pkg.Package, _ pkg.Context, _, _ []string) (match.Matches, []match.IgnoredMatch, error) {
	f.calls++
	f.packages = append(f.packages, packages...)
	if f.err != nil {
		return match.Matches{}, nil, f.err
	}
	matches := match.NewMatches()
	for _, p := range packages {
		for _, a := range f.advisories[p.Name+"@"+p.Version] {
			md := &vulnerability.Metadata{ID: a.id, Severity: a.severity}
			if a.kev {
				md.KnownExploited = []vulnerability.KnownExploited{{CVE: a.id}}
			}
			if a.epss > 0 {
				md.EPSS = []vulnerability.EPSS{{CVE: a.id, EPSS: a.epss}}
			}
			v := vulnerability.Vulnerability{
				Reference: vulnerability.Reference{ID: a.id},
				Fix:       vulnerability.Fix{Versions: a.fixedIn, State: vulnerability.FixStateFixed},
				Metadata:  md,
			}
			for _, r := range a.related {
				v.RelatedVulnerabilities = append(v.RelatedVulnerabilities, vulnerability.Reference{ID: r})
			}
			matches.Add(match.Match{Vulnerability: v, Package: p})
		}
	}
	return matches, nil, nil
}

func testIndex(t *testing.T) *k8scveindex.Index {
	t.Helper()
	ix, err := k8scveindex.Parse(strings.NewReader(testFeed))
	require.NoError(t, err)
	return ix
}

func version(c clustercomponents.Component, v string, a clustercomponents.Assessment) *clustercomponents.ComponentVersion {
	return &clustercomponents.ComponentVersion{Component: c, Version: v, RawVersion: "v" + v, Assessment: a}
}

func testOptions(t *testing.T, kinds ...Kind) Options {
	return Options{
		Kinds:       kinds,
		Index:       testIndex(t),
		IndexMaxAge: k8scveindex.DefaultMaxAge,
		Now:         time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC),
		DBBuilt:     time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC),
	}
}

func vulnIDs(t *testing.T, res Result, kind Kind, name string) []string {
	t.Helper()
	for _, r := range res.Resources {
		if r.GetKind() != string(kind) || r.GetName() != name {
			continue
		}
		data := r.GetObject()["data"].(map[string]any)
		ids := []string{}
		for _, v := range data["vulnerabilities"].([]any) {
			ids = append(ids, v.(map[string]any)["id"].(string))
		}
		return ids
	}
	t.Fatalf("no %s resource for %s", kind, name)
	return nil
}

func kubernetesAdvisories() map[string][]advisory {
	return map[string][]advisory{
		"k8s.io/kubernetes@v1.27.3": {
			{id: "GHSA-pxhw-596r-rwq5", related: []string{"CVE-2024-3177"}, severity: "Low", fixedIn: []string{"1.27.13"}},
			{id: "CVE-2023-3676", severity: "High", fixedIn: []string{"1.27.4"}},
		},
	}
}

func TestBuildAttributesKubernetesCVEsToTheirComponent(t *testing.T) {
	inv := clustercomponents.Inventory{
		APIServer: version(clustercomponents.APIServer, "1.27.3", clustercomponents.Verified),
		Nodes: []clustercomponents.Node{
			{Name: "linux-1", OperatingSystem: "linux", Kubelet: version(clustercomponents.Kubelet, "1.27.3", clustercomponents.Verified)},
			{Name: "windows-1", OperatingSystem: "windows", Kubelet: version(clustercomponents.Kubelet, "1.27.3", clustercomponents.Verified)},
		},
	}
	m := &fakeMatcher{advisories: kubernetesAdvisories()}

	res, err := Build(inv, m, testOptions(t, APIServerVulnerabilities, KubeletVulnerabilities))
	require.NoError(t, err)

	assert.Equal(t, 1, m.calls)
	assert.Len(t, m.packages, 1, "one lookup for the shared version")
	assert.Equal(t, []string{"CVE-2024-3177"}, vulnIDs(t, res, APIServerVulnerabilities, "kube-apiserver"))
	assert.Empty(t, vulnIDs(t, res, KubeletVulnerabilities, "linux-1"), "Windows-only CVE on a Linux node")
	assert.Equal(t, []string{"CVE-2023-3676"}, vulnIDs(t, res, KubeletVulnerabilities, "windows-1"))
	assert.Empty(t, res.Gaps)
}

func TestBuildFixedKubernetesVersionPasses(t *testing.T) {
	inv := clustercomponents.Inventory{APIServer: version(clustercomponents.APIServer, "1.28.9", clustercomponents.Verified)}
	m := &fakeMatcher{advisories: map[string][]advisory{}}

	res, err := Build(inv, m, testOptions(t, APIServerVulnerabilities))
	require.NoError(t, err)
	assert.Empty(t, vulnIDs(t, res, APIServerVulnerabilities, "kube-apiserver"))
	assert.Empty(t, res.Gaps)
}

func TestBuildRecordsUnattributedCVEsAsGaps(t *testing.T) {
	inv := clustercomponents.Inventory{
		Nodes: []clustercomponents.Node{
			{Name: "node-1", OperatingSystem: "linux", Kubelet: version(clustercomponents.Kubelet, "1.28.4", clustercomponents.Verified)},
		},
	}
	m := &fakeMatcher{advisories: map[string][]advisory{
		"k8s.io/kubernetes@v1.28.4": {{id: "CVE-2099-0001", severity: "High"}},
	}}

	res, err := Build(inv, m, testOptions(t, KubeletVulnerabilities))
	require.NoError(t, err)

	assert.Empty(t, vulnIDs(t, res, KubeletVulnerabilities, "node-1"))
	require.Len(t, res.Gaps, 1)
	assert.Equal(t, KubeletVulnerabilities, res.Gaps[0].Kind)
	assert.Equal(t, "node-1", res.Gaps[0].Selector)
	assert.Contains(t, res.Gaps[0].Reason, "CVE-2099-0001")
}

func TestBuildIndexProblemsAreGaps(t *testing.T) {
	inv := clustercomponents.Inventory{APIServer: version(clustercomponents.APIServer, "1.27.3", clustercomponents.Verified)}

	t.Run("stale index still attributes", func(t *testing.T) {
		opts := testOptions(t, APIServerVulnerabilities)
		opts.Now = opts.Index.Updated.Add(30 * 24 * time.Hour)
		res, err := Build(inv, &fakeMatcher{advisories: kubernetesAdvisories()}, opts)
		require.NoError(t, err)
		assert.Equal(t, []string{"CVE-2024-3177"}, vulnIDs(t, res, APIServerVulnerabilities, "kube-apiserver"))
		require.Len(t, res.Gaps, 1)
		assert.Equal(t, ClusterSelector, res.Gaps[0].Selector)
		assert.Contains(t, res.Gaps[0].Reason, "2026-10-01")
	})

	t.Run("missing index builds no Kubernetes resources", func(t *testing.T) {
		opts := testOptions(t, APIServerVulnerabilities)
		opts.Index = nil
		m := &fakeMatcher{advisories: kubernetesAdvisories()}
		res, err := Build(inv, m, opts)
		require.NoError(t, err)
		assert.Zero(t, m.calls, "nothing to match without the index")
		assert.Empty(t, res.Resources)
		require.Len(t, res.Gaps, 1)
		assert.Equal(t, APIServerVulnerabilities, res.Gaps[0].Kind)
	})
}

func TestBuildContainerRuntime(t *testing.T) {
	inv := clustercomponents.Inventory{
		Nodes: []clustercomponents.Node{
			{Name: "a", OperatingSystem: "linux", Runtime: version(clustercomponents.Containerd, "1.7.11", clustercomponents.Verified)},
			{Name: "b", OperatingSystem: "linux", Runtime: version(clustercomponents.Containerd, "2.0.0", clustercomponents.VendorBuild)},
			{Name: "c", OperatingSystem: "linux", Runtime: version(clustercomponents.CRIO, "1.29.1", clustercomponents.Verified)},
			{Name: "d", OperatingSystem: "linux"},
		},
		Gaps: []clustercomponents.Gap{{Component: clustercomponents.ContainerRuntime, Node: "d", Reason: `unsupported container runtime "docker"`}},
	}
	m := &fakeMatcher{advisories: map[string][]advisory{
		"github.com/containerd/containerd@v1.7.11": {
			{id: "CVE-2024-40635", severity: "Medium", fixedIn: []string{"1.7.27"}, epss: 0.0004},
			{id: "CVE-2024-0001", severity: "Low", kev: true},
			{id: "CVE-2024-0002", severity: "Critical"},
		},
	}}

	res, err := Build(inv, m, testOptions(t, ContainerRuntimeVulnerabilities))
	require.NoError(t, err)

	var names []string
	for _, p := range m.packages {
		names = append(names, p.Name+"@"+p.Version)
	}
	assert.ElementsMatch(t, []string{
		"github.com/containerd/containerd@v1.7.11",
		"github.com/containerd/containerd/v2@v2.0.0",
		"github.com/cri-o/cri-o@v1.29.1",
	}, names)

	assert.Equal(t, []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-40635"}, vulnIDs(t, res, ContainerRuntimeVulnerabilities, "a"), "known exploited first, then severity")
	assert.Empty(t, vulnIDs(t, res, ContainerRuntimeVulnerabilities, "b"))
	assert.Len(t, res.Resources, 3)

	for _, r := range res.Resources {
		if r.GetName() == "b" {
			assert.Equal(t, "vendor-build", r.GetObject()["data"].(map[string]any)["assessment"])
		}
	}
	require.Len(t, res.Gaps, 1)
	assert.Equal(t, Gap{Kind: ContainerRuntimeVulnerabilities, Selector: "d", Reason: `unsupported container runtime "docker"`}, res.Gaps[0])
}

func TestBuildOnlySelectedKinds(t *testing.T) {
	inv := clustercomponents.Inventory{
		APIServer: version(clustercomponents.APIServer, "1.28.4", clustercomponents.Verified),
		Nodes: []clustercomponents.Node{
			{Name: "n", OperatingSystem: "linux", Kubelet: version(clustercomponents.Kubelet, "1.28.4", clustercomponents.Verified)},
		},
		Gaps: []clustercomponents.Gap{{Component: clustercomponents.ContainerRuntime, Node: "n", Reason: "container runtime version not reported"}},
	}

	m := &fakeMatcher{}
	res, err := Build(inv, m, Options{})
	require.NoError(t, err)
	assert.Zero(t, m.calls)
	assert.Empty(t, res.Resources)
	assert.Empty(t, res.Gaps)

	res, err = Build(inv, m, testOptions(t, KubeletVulnerabilities))
	require.NoError(t, err)
	require.Len(t, res.Resources, 1)
	assert.Equal(t, string(KubeletVulnerabilities), res.Resources[0].GetKind())
	assert.Equal(t, APIVersion, res.Resources[0].GetApiVersion())
	assert.Empty(t, res.Gaps)
}

func TestBuildMatcherError(t *testing.T) {
	inv := clustercomponents.Inventory{APIServer: version(clustercomponents.APIServer, "1.28.4", clustercomponents.Verified)}
	_, err := Build(inv, &fakeMatcher{err: errors.New("db not loaded")}, testOptions(t, APIServerVulnerabilities))
	assert.ErrorContains(t, err, "db not loaded")
}

func TestToVulnerabilityMergesAdvisoriesOfOneCVE(t *testing.T) {
	inv := clustercomponents.Inventory{
		Nodes: []clustercomponents.Node{
			{Name: "a", OperatingSystem: "linux", Runtime: version(clustercomponents.Containerd, "1.7.11", clustercomponents.Verified)},
		},
	}
	m := &fakeMatcher{advisories: map[string][]advisory{
		"github.com/containerd/containerd@v1.7.11": {
			{id: "GHSA-aaaa", related: []string{"CVE-2024-40635"}, severity: "Medium", fixedIn: []string{"1.7.27"}},
			{id: "CVE-2024-40635", severity: "High", fixedIn: []string{"1.6.38"}, epss: 0.01},
		},
	}}

	res, err := Build(inv, m, testOptions(t, ContainerRuntimeVulnerabilities))
	require.NoError(t, err)
	require.Len(t, res.Resources, 1)
	vulns := res.Resources[0].GetObject()["data"].(map[string]any)["vulnerabilities"].([]any)
	require.Len(t, vulns, 1)
	v := vulns[0].(map[string]any)
	assert.Equal(t, "CVE-2024-40635", v["id"])
	assert.Equal(t, "High", v["severity"])
	assert.Equal(t, []any{"GHSA-aaaa"}, v["aliases"])
	assert.Equal(t, []any{"1.6.38", "1.7.27"}, v["fixedIn"])
	assert.InDelta(t, 0.01, v["epss"], 1e-9)
}
