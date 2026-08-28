package resourcehandler

import (
	"context"
	"slices"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	discoveryfake "k8s.io/client-go/discovery/fake"
	k8stesting "k8s.io/client-go/testing"
)

// clusterWithGatewayAPIDiscovery simulates a real cluster: it serves Pods
// (which the framework below has a control for) and Gateway API HTTPRoutes
// (which nothing in the framework references at all).
func clusterWithGatewayAPIDiscovery() *discoveryfake.FakeDiscovery {
	client := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	client.Resources = []*metav1.APIResourceList{
		{
			GroupVersion: "v1",
			APIResources: []metav1.APIResource{
				{Name: "pods", Kind: "Pod", Namespaced: true, Verbs: metav1.Verbs{"get", "list", "watch"}},
			},
		},
		{
			GroupVersion: "gateway.networking.k8s.io/v1",
			APIResources: []metav1.APIResource{
				{Name: "httproutes", Kind: "HTTPRoute", Namespaced: true, Verbs: metav1.Verbs{"get", "list", "watch"}},
				{Name: "gateways", Kind: "Gateway", Namespaced: true, Verbs: metav1.Verbs{"get", "list", "watch"}},
			},
		},
	}
	return client
}

// TestComputeUnexaminedKinds_ReturnsQueriedKindsGap covers the core diff logic:
// discovered kinds no rule matched are returned, discovered kinds the policy
// did query are not, and non-listable kinds are excluded regardless.
func TestComputeUnexaminedKinds_ReturnsQueriedKindsGap(t *testing.T) {
	resolver, failures, discovered := newDiscoveryResourceResolverWithKinds(clusterWithGatewayAPIDiscovery())
	require.Empty(t, failures)
	require.Len(t, discovered, 3, "expected Pod, HTTPRoute and Gateway from discovery")

	pods := resolver("", "v1", "Pod")
	require.Len(t, pods, 1)
	queryable := QueryableResources{
		pods[0].groupVersionResourceTriplet: QueryableResource{GroupVersionResourceTriplet: pods[0].groupVersionResourceTriplet},
	}

	unexamined := computeUnexaminedKinds(discovered, queryable)
	require.Len(t, unexamined, 2)
	assert.Equal(t, "gateway.networking.k8s.io/v1/gateways", unexamined[0].GroupVersionResource)
	assert.Equal(t, "Gateway", unexamined[0].Kind)
	assert.Equal(t, "gateway.networking.k8s.io/v1/httproutes", unexamined[1].GroupVersionResource)
	assert.Equal(t, "HTTPRoute", unexamined[1].Kind)
}

// TestComputeUnexaminedKinds_EmptyWhenEverythingQueried guards against false
// positives: a queryable set that already names every discovered kind must
// report no gap.
func TestComputeUnexaminedKinds_EmptyWhenEverythingQueried(t *testing.T) {
	_, _, discovered := newDiscoveryResourceResolverWithKinds(clusterWithGatewayAPIDiscovery())

	queryable := QueryableResources{
		"/v1/pods": QueryableResource{GroupVersionResourceTriplet: "/v1/pods"},
		"gateway.networking.k8s.io/v1/httproutes": QueryableResource{GroupVersionResourceTriplet: "gateway.networking.k8s.io/v1/httproutes"},
		"gateway.networking.k8s.io/v1/gateways":   QueryableResource{GroupVersionResourceTriplet: "gateway.networking.k8s.io/v1/gateways"},
	}

	assert.Empty(t, computeUnexaminedKinds(discovered, queryable))
}

// TestGetResources_PopulatesUnexaminedKinds drives the real production path:
// a framework matching only Pod, against a cluster whose discovery also
// serves Gateway API. GetResources must populate sessionObj.UnexaminedKinds
// with the kinds the framework never asked about.
func TestGetResources_PopulatesUnexaminedKinds(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()
	handler := getResourceHandlerMock()
	handler.k8s.DiscoveryClient = clusterWithGatewayAPIDiscovery()
	handler.k8s.DynamicClient = &mockDynamicClient{
		listFunc: func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			return &unstructured.UnstructuredList{
				Items: []unstructured.Unstructured{{
					Object: map[string]any{
						"apiVersion": "v1",
						"kind":       "Pod",
						"metadata":   map[string]any{"name": "test-pod", "namespace": "default"},
					},
				}},
			}, nil
		},
	}

	rule := mockRule("rule-a", []reporthandling.RuleMatchObjects{mockMatch(1)}, "")
	control := mockControl("control-1", []reporthandling.PolicyRule{rule})
	framework := mockFramework("test", []reporthandling.Control{control})

	scanInfo := &cautils.ScanInfo{}
	sessionObj := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
	sessionObj.Policies = append(sessionObj.Policies, *framework)

	_, _, _, _, err := handler.GetResources(context.Background(), sessionObj, scanInfo)
	require.NoError(t, err)

	var triplets []string
	for _, k := range sessionObj.UnexaminedKinds {
		triplets = append(triplets, k.GroupVersionResource)
	}
	assert.Contains(t, triplets, "gateway.networking.k8s.io/v1/httproutes")
	assert.Contains(t, triplets, "gateway.networking.k8s.io/v1/gateways")
}

// TestGetResources_ExcludeKindsIsNotReportedAsUnexamined guards against
// treating a deliberate --exclude-kinds narrowing as a policy coverage gap. A
// control matching Deployment exists in the framework; --exclude-kinds
// Deployment removes it from the query set, but a control did examine it, so
// it must not show up in UnexaminedKinds.
func TestGetResources_ExcludeKindsIsNotReportedAsUnexamined(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()
	handler := getResourceHandlerMock()
	discovery := clusterWithGatewayAPIDiscovery()
	discovery.Resources = append(discovery.Resources, &metav1.APIResourceList{
		GroupVersion: "apps/v1",
		APIResources: []metav1.APIResource{
			{Name: "deployments", Kind: "Deployment", Namespaced: true, Verbs: metav1.Verbs{"get", "list", "watch"}},
		},
	})
	handler.k8s.DiscoveryClient = discovery
	handler.k8s.DynamicClient = &mockDynamicClient{
		listFunc: func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			return &unstructured.UnstructuredList{}, nil
		},
	}

	rule := mockRule("rule-a", []reporthandling.RuleMatchObjects{mockMatch(2)}, "")
	control := mockControl("control-1", []reporthandling.PolicyRule{rule})
	framework := mockFramework("test", []reporthandling.Control{control})

	scanInfo := &cautils.ScanInfo{ExcludeKinds: "Deployment"}
	sessionObj := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
	sessionObj.Policies = append(sessionObj.Policies, *framework)

	_, _, _, _, err := handler.GetResources(context.Background(), sessionObj, scanInfo)
	require.NoError(t, err)

	var triplets []string
	for _, k := range sessionObj.UnexaminedKinds {
		triplets = append(triplets, k.GroupVersionResource)
	}
	assert.NotContains(t, triplets, "apps/v1/deployments",
		"a control examines Deployment; excluding it via --exclude-kinds must not be reported as a coverage gap")
}

// TestGetResources_SingleResourceScanSkipsUnexaminedKinds guards the other
// case matthyx flagged: a single-resource scan deliberately narrows the query
// set to one object, so it has no cluster-wide coverage question to answer.
func TestGetResources_SingleResourceScanSkipsUnexaminedKinds(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()
	handler := getResourceHandlerMock()
	handler.k8s.DiscoveryClient = clusterWithGatewayAPIDiscovery()
	handler.k8s.DynamicClient = &mockDynamicClient{
		listFunc: func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			return &unstructured.UnstructuredList{
				Items: []unstructured.Unstructured{{
					Object: map[string]any{
						"apiVersion": "v1",
						"kind":       "Pod",
						"metadata":   map[string]any{"name": "test-pod", "namespace": "default"},
					},
				}},
			}, nil
		},
	}

	rule := mockRule("rule-a", []reporthandling.RuleMatchObjects{mockMatch(1)}, "")
	control := mockControl("control-1", []reporthandling.PolicyRule{rule})
	framework := mockFramework("test", []reporthandling.Control{control})

	scanInfo := &cautils.ScanInfo{
		ScanObject: &objectsenvelopes.ScanObject{
			ApiVersion: "v1",
			Kind:       "Pod",
			Metadata:   objectsenvelopes.ScanObjectMetadata{Name: "test-pod", Namespace: "default"},
		},
	}
	sessionObj := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
	sessionObj.Policies = append(sessionObj.Policies, *framework)

	_, _, _, _, err := handler.GetResources(context.Background(), sessionObj, scanInfo)
	require.NoError(t, err)
	require.NotNil(t, sessionObj.SingleResourceScan)

	assert.Empty(t, sessionObj.UnexaminedKinds,
		"a single-resource scan has no cluster-wide coverage question to answer")
}

// TestStreamResourcesBatches_PopulatesUnexaminedKinds mirrors
// TestGetResources_PopulatesUnexaminedKinds on the streaming entry point, so
// the two collection paths cannot silently diverge on this field the way
// --skip-controls once did between the eager and streaming pipelines.
func TestStreamResourcesBatches_PopulatesUnexaminedKinds(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()
	handler := getResourceHandlerMock()
	handler.k8s.DiscoveryClient = clusterWithGatewayAPIDiscovery()
	handler.k8s.DynamicClient = &mockDynamicClient{
		listFunc: func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			return &unstructured.UnstructuredList{
				Items: []unstructured.Unstructured{{
					Object: map[string]any{
						"apiVersion": "v1",
						"kind":       "Pod",
						"metadata":   map[string]any{"name": "test-pod", "namespace": "default"},
					},
				}},
			}, nil
		},
	}

	rule := mockRule("rule-a", []reporthandling.RuleMatchObjects{mockMatch(1)}, "")
	control := mockControl("control-1", []reporthandling.PolicyRule{rule})
	framework := mockFramework("test", []reporthandling.Control{control})

	scanInfo := &cautils.ScanInfo{}
	sessionObj := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
	sessionObj.Policies = append(sessionObj.Policies, *framework)

	batchChan, errChan, _, err := handler.StreamResourcesBatches(context.Background(), sessionObj, scanInfo)
	require.NoError(t, err)
	for range batchChan {
	}
	require.NoError(t, <-errChan)

	var triplets []string
	for _, k := range sessionObj.UnexaminedKinds {
		triplets = append(triplets, k.GroupVersionResource)
	}
	assert.Contains(t, triplets, "gateway.networking.k8s.io/v1/httproutes")
	assert.Contains(t, triplets, "gateway.networking.k8s.io/v1/gateways")
}

// clusterWithMultiVersionDiscovery serves two kinds at two versions each: a
// CRD the way Agent Sandbox registers one (v1alpha1 alongside v1beta1), and a
// built-in group an ordinary cluster already has (autoscaling v1 and v2).
func clusterWithMultiVersionDiscovery() *discoveryfake.FakeDiscovery {
	client := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	client.Resources = []*metav1.APIResourceList{
		{
			GroupVersion: "agents.x-k8s.io/v1alpha1",
			APIResources: []metav1.APIResource{
				{Name: "sandboxes", Kind: "Sandbox", Namespaced: true, Verbs: metav1.Verbs{"get", "list", "watch"}},
			},
		},
		{
			GroupVersion: "agents.x-k8s.io/v1beta1",
			APIResources: []metav1.APIResource{
				{Name: "sandboxes", Kind: "Sandbox", Namespaced: true, Verbs: metav1.Verbs{"get", "list", "watch"}},
			},
		},
		{
			GroupVersion: "autoscaling/v1",
			APIResources: []metav1.APIResource{
				{Name: "horizontalpodautoscalers", Kind: "HorizontalPodAutoscaler", Namespaced: true, Verbs: metav1.Verbs{"get", "list", "watch"}},
			},
		},
		{
			GroupVersion: "autoscaling/v2",
			APIResources: []metav1.APIResource{
				{Name: "horizontalpodautoscalers", Kind: "HorizontalPodAutoscaler", Namespaced: true, Verbs: metav1.Verbs{"get", "list", "watch"}},
			},
		},
	}
	return client
}

func queryableFrom(triplets ...string) QueryableResources {
	queryable := QueryableResources{}
	for _, triplet := range triplets {
		queryable[triplet] = QueryableResource{GroupVersionResourceTriplet: triplet}
	}
	return queryable
}

func unexaminedTriplets(kinds []cautils.UnexaminedKind) []string {
	var triplets []string
	for _, kind := range kinds {
		triplets = append(triplets, kind.GroupVersionResource)
	}
	return triplets
}

// TestComputeUnexaminedKinds_QueriedVersionExaminesEveryServedVersion pins the
// core of the fix: a LIST at one served version returns every object of that
// kind, so the versions the rule did not name are not coverage gaps.
func TestComputeUnexaminedKinds_QueriedVersionExaminesEveryServedVersion(t *testing.T) {
	_, _, discovered := newDiscoveryResourceResolverWithKinds(clusterWithMultiVersionDiscovery())
	require.Len(t, discovered, 4)

	queryable := queryableFrom(
		"agents.x-k8s.io/v1beta1/sandboxes",
		"autoscaling/v2/horizontalpodautoscalers",
	)

	assert.Empty(t, computeUnexaminedKinds(discovered, queryable),
		"every Sandbox and HorizontalPodAutoscaler was examined; the other served version of each is the same objects")
}

// TestComputeUnexaminedKinds_ResourceNameInAnotherGroupIsStillAGap is the
// regression risk of dropping the version from the comparison: only the
// version may be ignored. Two groups serving the same resource name are
// distinct resources backed by distinct storage, so querying one must not
// clear the other.
func TestComputeUnexaminedKinds_ResourceNameInAnotherGroupIsStillAGap(t *testing.T) {
	client := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	client.Resources = []*metav1.APIResourceList{
		{
			GroupVersion: "extensions/v1beta1",
			APIResources: []metav1.APIResource{
				{Name: "ingresses", Kind: "Ingress", Namespaced: true, Verbs: metav1.Verbs{"get", "list", "watch"}},
			},
		},
		{
			GroupVersion: "networking.k8s.io/v1",
			APIResources: []metav1.APIResource{
				{Name: "ingresses", Kind: "Ingress", Namespaced: true, Verbs: metav1.Verbs{"get", "list", "watch"}},
			},
		},
	}
	_, _, discovered := newDiscoveryResourceResolverWithKinds(client)

	unexamined := computeUnexaminedKinds(discovered, queryableFrom("extensions/v1beta1/ingresses"))

	assert.Equal(t, []string{"networking.k8s.io/v1/ingresses"}, unexaminedTriplets(unexamined))
}

// TestComputeUnexaminedKinds_MultiVersionGapReportedOnce covers a kind no rule
// examined at any version: that is one coverage gap, reported at the version an
// apiserver ranks highest, not one row per served version.
func TestComputeUnexaminedKinds_MultiVersionGapReportedOnce(t *testing.T) {
	_, _, discovered := newDiscoveryResourceResolverWithKinds(clusterWithMultiVersionDiscovery())

	unexamined := computeUnexaminedKinds(discovered, QueryableResources{})

	assert.Equal(t, []string{
		"agents.x-k8s.io/v1beta1/sandboxes",
		"autoscaling/v2/horizontalpodautoscalers",
	}, unexaminedTriplets(unexamined))
}

// TestComputeUnexaminedKinds_ReportedVersionIgnoresDiscoveryOrder pins that
// the version a gap is reported at comes from the apiserver's own version
// ranking rather than from whichever group discovery happened to list first.
func TestComputeUnexaminedKinds_ReportedVersionIgnoresDiscoveryOrder(t *testing.T) {
	client := clusterWithMultiVersionDiscovery()
	slices.Reverse(client.Resources)
	_, _, discovered := newDiscoveryResourceResolverWithKinds(client)

	unexamined := computeUnexaminedKinds(discovered, QueryableResources{})

	assert.Equal(t, []string{
		"agents.x-k8s.io/v1beta1/sandboxes",
		"autoscaling/v2/horizontalpodautoscalers",
	}, unexaminedTriplets(unexamined))
}

// TestGetResources_MultiVersionCRDQueriedAtOneVersionIsNoGap drives the same
// case through the real collection path: a control naming the CRD at one of
// the two versions the cluster serves it at leaves no coverage gap behind.
func TestGetResources_MultiVersionCRDQueriedAtOneVersionIsNoGap(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()
	handler := getResourceHandlerMock()
	handler.k8s.DiscoveryClient = clusterWithMultiVersionDiscovery()
	handler.k8s.DynamicClient = &mockDynamicClient{
		listFunc: func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			return &unstructured.UnstructuredList{}, nil
		},
	}

	match := reporthandling.RuleMatchObjects{
		APIGroups:   []string{"agents.x-k8s.io"},
		APIVersions: []string{"v1beta1"},
		Resources:   []string{"Sandbox"},
	}
	rule := mockRule("rule-a", []reporthandling.RuleMatchObjects{match}, "")
	control := mockControl("control-1", []reporthandling.PolicyRule{rule})
	framework := mockFramework("test", []reporthandling.Control{control})

	scanInfo := &cautils.ScanInfo{}
	sessionObj := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
	sessionObj.Policies = append(sessionObj.Policies, *framework)

	_, _, _, _, err := handler.GetResources(context.Background(), sessionObj, scanInfo)
	require.NoError(t, err)

	assert.NotContains(t, unexaminedTriplets(sessionObj.UnexaminedKinds), "agents.x-k8s.io/v1alpha1/sandboxes",
		"the control examines Sandbox; the version it did not name is not a coverage gap")
}
