package resourcehandler

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
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
