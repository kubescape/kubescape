package resourcehandler

import (
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	discoveryfake "k8s.io/client-go/discovery/fake"
	k8stesting "k8s.io/client-go/testing"
)

// coreGroupDiscovery serves the core group the way a cluster does: as the empty
// API group, which is the spelling a "core" rule has to be reconciled with.
func coreGroupDiscovery() *discoveryfake.FakeDiscovery {
	discovery := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	discovery.Resources = []*metav1.APIResourceList{
		{
			GroupVersion: "v1",
			APIResources: []metav1.APIResource{
				{Name: "pods", Kind: "Pod", Namespaced: true, Verbs: metav1.Verbs{"get", "list"}},
				{Name: "nodes", Kind: "Node", Namespaced: false, Verbs: metav1.Verbs{"get", "list"}},
			},
		},
	}
	return discovery
}

func TestDiscoveryResolverMatchesCoreGroupSpelling(t *testing.T) {
	resolver, failures := newDiscoveryResourceResolver(coreGroupDiscovery())
	require.Empty(t, failures)

	tests := []struct {
		name           string
		group          string
		resource       string
		wantTriplet    string
		wantKind       string
		wantNamespaced bool
	}{
		{name: "core spelling", group: "core", resource: "Pod", wantTriplet: "/v1/pods", wantKind: "Pod", wantNamespaced: true},
		{name: "empty spelling", group: "", resource: "Pod", wantTriplet: "/v1/pods", wantKind: "Pod", wantNamespaced: true},
		{name: "core spelling by plural", group: "core", resource: "pods", wantTriplet: "/v1/pods", wantKind: "Pod", wantNamespaced: true},
		{name: "core spelling cluster scoped", group: "core", resource: "Node", wantTriplet: "/v1/nodes", wantKind: "Node", wantNamespaced: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolved := resolver(test.group, "v1", test.resource)
			require.Len(t, resolved, 1)
			assert.Equal(t, test.wantTriplet, resolved[0].groupVersionResourceTriplet)
			assert.Equal(t, test.wantKind, resolved[0].kind)
			require.NotNil(t, resolved[0].namespaced)
			assert.Equal(t, test.wantNamespaced, *resolved[0].namespaced)
		})
	}
}

// A "core" rule used to fall past discovery into the built-in fallback, which
// synthesized a triplet naming an API group no cluster serves.
func TestDefaultResolverDropsCoreGroupFromTriplet(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()

	tests := []struct {
		name     string
		group    string
		resource string
		want     []string
	}{
		{name: "core spelling", group: "core", resource: "secrets", want: []string{"/v1/secrets"}},
		{name: "empty spelling", group: "", resource: "secrets", want: []string{"/v1/secrets"}},
		{name: "named group untouched", group: "apps", resource: "deployments", want: []string{"apps/v1/deployments"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolved := defaultResourceResolver(test.group, "v1", test.resource)
			triplets := make([]string, 0, len(resolved))
			for _, r := range resolved {
				triplets = append(triplets, r.groupVersionResourceTriplet)
			}
			assert.Equal(t, test.want, triplets)
		})
	}
}

// The core group has no custom resources, so a rule naming one is a typo rather
// than a resource worth guessing a live query for.
func TestDefaultResolverSkipsUnknownCoreGroupResource(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()

	assert.Empty(t, defaultResourceResolver("core", "v1", "sandboxes"))
}

func TestOfflineResolverMatchesCoreGroupSpelling(t *testing.T) {
	workload := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata":   map[string]any{"name": "creds", "namespace": "ns1"},
	})
	resolver := newOfflineManifestResourceResolver(map[string][]workloadinterface.IMetadata{
		k8sinterface.JoinResourceTriplets("", "v1", "secrets"): {workload},
	})

	coreSpelling := resolver("core", "v1", "Secret")
	require.Len(t, coreSpelling, 1)
	assert.Equal(t, "Secret", coreSpelling[0].kind)
	assert.Equal(t, resolver("", "v1", "Secret"), coreSpelling)
	assert.Contains(t, append(coreSpelling[0].comparisonTriplets, coreSpelling[0].groupVersionResourceTriplet), "/v1/secrets")
}

func TestDiscoveryFailureAttributionMatchesCoreGroupSpelling(t *testing.T) {
	framework := reporthandling.Framework{Controls: []reporthandling.Control{
		discoveryDependencyControl("C-POD", "core", "v1", "Pod"),
	}}
	resourceToControls := make(map[string][]string)

	recordDiscoveryFailureDependencies(
		[]reporthandling.Framework{framework}, nil, reporthandling.ScopeCluster,
		func(string, string, string) []resolvedResource { return nil },
		[]cautils.PartialGVRPull{{GVR: "discovery:v1", Selector: "discovery", Error: "forbidden"}},
		resourceToControls, make(map[string]struct{}),
	)

	assert.Equal(t, map[string][]string{"discovery:v1": {"C-POD"}}, resourceToControls)
}
