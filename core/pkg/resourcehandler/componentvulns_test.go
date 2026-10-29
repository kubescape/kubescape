package resourcehandler

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/componentvulns"
	"github.com/kubescape/kubescape/v4/core/pkg/k8scveindex"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	reportv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
)

const (
	kubeletVulnsGVR = componentvulns.APIVersion + "/KubeletVulnerabilities"
	runtimeVulnsGVR = componentvulns.APIVersion + "/ContainerRuntimeVulnerabilities"
)

type stubComponentMatcher struct{ calls int }

func (s *stubComponentMatcher) MatchPackages(packages []pkg.Package, _ pkg.Context, _, _ []string) (match.Matches, []match.IgnoredMatch, error) {
	s.calls++
	matches := match.NewMatches()
	for _, p := range packages {
		if p.Name == "github.com/containerd/containerd" && p.Version == "v1.7.11" {
			matches.Add(match.Match{
				Package: p,
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{ID: "CVE-2024-40635"},
					Fix:       vulnerability.Fix{Versions: []string{"1.7.27"}, State: vulnerability.FixStateFixed},
					Metadata:  &vulnerability.Metadata{ID: "CVE-2024-40635", Severity: "Medium"},
				},
			})
		}
	}
	return matches, nil, nil
}

func componentVulnNode(name, kubelet, runtime string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{
			OperatingSystem:         "linux",
			KubeletVersion:          kubelet,
			ContainerRuntimeVersion: runtime,
		}},
	}
}

func componentVulnSession(t *testing.T, controls ...reporthandling.Control) (*cautils.OPASessionObj, cautils.ExternalResources) {
	t.Helper()
	resolver, _ := newDiscoveryResourceResolver(coreGroupDiscovery())
	resourceToControl := map[string][]string{}
	frameworks := []reporthandling.Framework{{Controls: controls}}
	ksResourceMap := setKSResourceMap(frameworks, resourceToControl, resolver)
	return &cautils.OPASessionObj{
		Policies:              frameworks,
		InfoMap:               map[string]apis.StatusInfo{},
		ResourceToControlsMap: resourceToControl,
		Report:                &reportv2.PostureReport{ClusterAPIServerInfo: &version.Info{GitVersion: "v1.28.4"}},
	}, ksResourceMap
}

func componentVulnControl(id string, kinds ...string) reporthandling.Control {
	return reporthandling.Control{ControlID: id, Rules: []reporthandling.PolicyRule{{Match: []reporthandling.RuleMatchObjects{
		{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Node"}},
		{APIGroups: []string{componentvulns.Group}, APIVersions: []string{componentvulns.Version}, Resources: kinds},
	}}}}
}

func TestCollectComponentVulnerabilities(t *testing.T) {
	sessionObj, ksResourceMap := componentVulnSession(t, componentVulnControl("C-RUNTIME", "ContainerRuntimeVulnerabilities"))
	require.Contains(t, ksResourceMap, runtimeVulnsGVR)

	stub := &stubComponentMatcher{}
	handler := &K8sResourceHandler{
		k8s: &k8sinterface.KubernetesApi{KubernetesClient: fakeclientset.NewClientset(
			componentVulnNode("a", "v1.28.4", "containerd://1.7.11"),
			componentVulnNode("b", "v1.28.4", "containerd://1.7.11"),
			componentVulnNode("c", "v1.28.4", "docker://24.0.7"),
		)},
		componentVulnSources: func(context.Context, *cautils.ScanInfo) (componentVulnSources, error) {
			return componentVulnSources{matcher: stub, dbBuilt: time.Now()}, nil
		},
	}

	allResources := map[string]workloadinterface.IMetadata{}
	handler.collectComponentVulnerabilities(context.Background(), sessionObj, &cautils.ScanInfo{}, allResources, ksResourceMap)

	assert.Equal(t, 1, stub.calls)
	require.Len(t, ksResourceMap[runtimeVulnsGVR], 2)
	for _, id := range ksResourceMap[runtimeVulnsGVR] {
		r := allResources[id]
		require.NotNil(t, r)
		vulns := r.GetObject()["data"].(map[string]any)["vulnerabilities"].([]any)
		require.Len(t, vulns, 1)
		assert.Equal(t, "CVE-2024-40635", vulns[0].(map[string]any)["id"])
	}
	assert.NotContains(t, ksResourceMap, kubeletVulnsGVR, "unselected kinds are not built")

	require.Len(t, sessionObj.PartialGVRFailures, 1)
	gap := sessionObj.PartialGVRFailures[0]
	assert.Equal(t, runtimeVulnsGVR, gap.GVR)
	assert.Equal(t, "c", gap.Selector)
	assert.Contains(t, gap.Error, "docker")
	assert.NotContains(t, sessionObj.InfoMap, runtimeVulnsGVR)

	coverage := cautils.BuildScanCoverage(sessionObj.InfoMap, sessionObj.ResourceToControlsMap, nil, sessionObj.PartialGVRFailures, nil, nil)
	assert.Equal(t, sessionObj.PartialGVRFailures, coverage.PartialGVRPulls)
	assert.Less(t, coverage.CoverageScore, float32(100), "a node that could not be assessed lowers coverage")
}

func TestCollectComponentVulnerabilitiesSkipsUnassessableKinds(t *testing.T) {
	t.Run("database fails to load", func(t *testing.T) {
		sessionObj, ksResourceMap := componentVulnSession(t, componentVulnControl("C-RUNTIME", "ContainerRuntimeVulnerabilities"))
		handler := &K8sResourceHandler{
			k8s: &k8sinterface.KubernetesApi{KubernetesClient: fakeclientset.NewClientset(componentVulnNode("a", "v1.28.4", "containerd://1.7.11"))},
			componentVulnSources: func(context.Context, *cautils.ScanInfo) (componentVulnSources, error) {
				return componentVulnSources{}, errors.New("vulnerability database is not loaded")
			},
		}
		handler.collectComponentVulnerabilities(context.Background(), sessionObj, &cautils.ScanInfo{}, map[string]workloadinterface.IMetadata{}, ksResourceMap)

		info, ok := sessionObj.InfoMap[runtimeVulnsGVR]
		require.True(t, ok)
		assert.Equal(t, apis.StatusSkipped, info.InnerStatus)
		assert.Contains(t, info.InnerInfo, "not loaded")
	})

	t.Run("no node can be assessed", func(t *testing.T) {
		sessionObj, ksResourceMap := componentVulnSession(t, componentVulnControl("C-KUBELET", "KubeletVulnerabilities"))
		index, err := k8scveindex.Parse(strings.NewReader(`{"_kubernetes_io":{"updated_at":"2099-01-01T00:00:00Z"},"items":[{"id":"CVE-2024-3177","content_text":""}]}`))
		require.NoError(t, err)
		handler := &K8sResourceHandler{
			k8s: &k8sinterface.KubernetesApi{KubernetesClient: fakeclientset.NewClientset(componentVulnNode("a", "v1.31.0-alpha.1", "containerd://1.7.11"))},
			componentVulnSources: func(context.Context, *cautils.ScanInfo) (componentVulnSources, error) {
				return componentVulnSources{matcher: &stubComponentMatcher{}, index: index}, nil
			},
		}
		handler.collectComponentVulnerabilities(context.Background(), sessionObj, &cautils.ScanInfo{}, map[string]workloadinterface.IMetadata{}, ksResourceMap)

		assert.Empty(t, ksResourceMap[kubeletVulnsGVR])
		info, ok := sessionObj.InfoMap[kubeletVulnsGVR]
		require.True(t, ok)
		assert.Equal(t, apis.StatusSkipped, info.InnerStatus)
		assert.Contains(t, info.InnerInfo, "pre-release")
		require.Len(t, sessionObj.PartialGVRFailures, 1)
		assert.Equal(t, "a", sessionObj.PartialGVRFailures[0].Selector)

		coverage := cautils.BuildScanCoverage(sessionObj.InfoMap, sessionObj.ResourceToControlsMap, nil, sessionObj.PartialGVRFailures, nil, nil)
		require.Len(t, coverage.FailedGVRPulls, 1)
		assert.Equal(t, kubeletVulnsGVR, coverage.FailedGVRPulls[0].GVR)
		assert.Less(t, coverage.CoverageScore, float32(100))
	})
}

func TestCollectComponentVulnerabilitiesNotSelected(t *testing.T) {
	sessionObj, ksResourceMap := componentVulnSession(t, reporthandling.Control{ControlID: "C-0001", Rules: []reporthandling.PolicyRule{{Match: []reporthandling.RuleMatchObjects{
		{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Node"}},
	}}}})
	handler := &K8sResourceHandler{
		componentVulnSources: func(context.Context, *cautils.ScanInfo) (componentVulnSources, error) {
			t.Fatal("vulnerability database loaded for a scan that does not need it")
			return componentVulnSources{}, nil
		},
	}
	handler.collectComponentVulnerabilities(context.Background(), sessionObj, &cautils.ScanInfo{}, map[string]workloadinterface.IMetadata{}, ksResourceMap)
	assert.Empty(t, sessionObj.PartialGVRFailures)
	assert.Empty(t, sessionObj.InfoMap)
}
