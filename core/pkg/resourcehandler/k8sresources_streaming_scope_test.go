package resourcehandler

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	discoveryfake "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/dynamic/fake"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

type streamingScopeTestCase struct {
	group                string
	version              string
	resource             string
	kind                 string
	name                 string
	namespace            string
	discoveredNamespaced *bool
	wantScope            string
}

func TestCollectAndStreamBatches_UsesDiscoveredScopeForNamespacedCRD(t *testing.T) {
	namespaced := true
	assertStreamingScopePartition(t, streamingScopeTestCase{
		group:                "example.com",
		version:              "v1",
		resource:             "widgets",
		kind:                 "Widget",
		name:                 "sample-widget",
		namespace:            "tenant-a",
		discoveredNamespaced: &namespaced,
		wantScope:            "tenant-a",
	})
}

func TestCollectAndStreamBatches_PreservesScopeContract(t *testing.T) {
	namespaced := true
	clusterScoped := false
	tests := []struct {
		name string
		streamingScopeTestCase
	}{
		{
			name: "discovery-confirmed cluster scope overrides the built-in Kind fallback",
			streamingScopeTestCase: streamingScopeTestCase{
				group:                "example.com",
				version:              "v1",
				resource:             "clusterpods",
				kind:                 "Pod",
				name:                 "sample-cluster-pod",
				namespace:            "tenant-a",
				discoveredNamespaced: &clusterScoped,
				wantScope:            cautils.ClusterScope,
			},
		},
		{
			name: "unknown scope retains the built-in kind fallback",
			streamingScopeTestCase: streamingScopeTestCase{
				version:   "v1",
				resource:  "pods",
				kind:      "Pod",
				name:      "sample-pod",
				namespace: "tenant-a",
				wantScope: "tenant-a",
			},
		},
		{
			name: "core Namespace retains its own named batch",
			streamingScopeTestCase: streamingScopeTestCase{
				version:              "v1",
				resource:             "namespaces",
				kind:                 "Namespace",
				name:                 "tenant-a",
				discoveredNamespaced: &clusterScoped,
				wantScope:            "tenant-a",
			},
		},
		{
			name: "namespaced object without a namespace remains resident",
			streamingScopeTestCase: streamingScopeTestCase{
				group:                "example.com",
				version:              "v1",
				resource:             "widgets",
				kind:                 "Widget",
				name:                 "orphan-widget",
				discoveredNamespaced: &namespaced,
				wantScope:            cautils.ClusterScope,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertStreamingScopePartition(t, tt.streamingScopeTestCase)
		})
	}
}

func assertStreamingScopePartition(t *testing.T, testCase streamingScopeTestCase) {
	t.Helper()
	ctx := context.Background()
	gvr := schema.GroupVersionResource{
		Group:    testCase.group,
		Version:  testCase.version,
		Resource: testCase.resource,
	}
	triplet := k8sinterface.GroupVersionResourceToString(&gvr)
	namespaced := testCase.discoveredNamespaced
	resolver := resourceResolver(defaultResourceResolver)

	if testCase.discoveredNamespaced != nil {
		discovery := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
		discovery.Resources = []*metav1.APIResourceList{{
			GroupVersion: schema.GroupVersion{Group: testCase.group, Version: testCase.version}.String(),
			APIResources: []metav1.APIResource{{
				Name:       testCase.resource,
				Kind:       testCase.kind,
				Namespaced: *testCase.discoveredNamespaced,
				Verbs:      metav1.Verbs{"get", "list"},
			}},
		}}
		var failures []cautils.PartialGVRPull
		resolver, failures = newDiscoveryResourceResolver(discovery)
		require.Empty(t, failures)

		resolved := resolver(testCase.group, testCase.version, testCase.kind)
		require.Len(t, resolved, 1)
		require.NotNil(t, resolved[0].namespaced)
		require.Equal(t, *testCase.discoveredNamespaced, *resolved[0].namespaced)
		triplet = resolved[0].groupVersionResourceTriplet
		namespaced = resolved[0].namespaced
	}

	metadata := map[string]any{"name": testCase.name}
	if testCase.namespace != "" {
		metadata["namespace"] = testCase.namespace
	}
	apiVersion := schema.GroupVersion{Group: testCase.group, Version: testCase.version}.String()
	list := &unstructured.UnstructuredList{
		Object: map[string]any{
			"apiVersion": apiVersion,
			"kind":       testCase.kind + "List",
		},
		Items: []unstructured.Unstructured{{Object: map[string]any{
			"apiVersion": apiVersion,
			"kind":       testCase.kind,
			"metadata":   metadata,
		}}},
	}
	handler := newStreamingScopeTestHandler(t, gvr, list)
	scanInfo, session := streamingTestSession(ctx)
	queryable := QueryableResources{triplet: {
		GroupVersionResourceTriplet: triplet,
		Namespaced:                  namespaced,
	}}
	batches := make(chan *cautils.ResourceBatch, 2)

	err := handler.collectAndStreamBatches(
		ctx,
		queryable,
		&EmptySelector{},
		session,
		scanInfo,
		cautils.ExternalResources{},
		batches,
		resolver,
	)
	require.NoError(t, err)

	resident := <-batches
	if testCase.wantScope == cautils.ClusterScope {
		assert.Len(t, resident.AllResources, 1)
		assert.Empty(t, batches)
		return
	}

	assert.Empty(t, resident.AllResources)
	require.Len(t, batches, 1)
	namespaceBatch := <-batches
	assert.Equal(t, testCase.wantScope, namespaceBatch.Scope)
	assert.Len(t, namespaceBatch.AllResources, 1)
}

func newStreamingScopeTestHandler(t *testing.T, gvr schema.GroupVersionResource, list *unstructured.UnstructuredList) *K8sResourceHandler {
	t.Helper()
	dynamicClient := fake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{gvr: list.GetKind()},
	)
	dynamicClient.PrependReactor("list", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		require.Equal(t, gvr, action.GetResource())
		return true, list, nil
	})
	client := fakeclientset.NewClientset()
	k8s := &k8sinterface.KubernetesApi{
		KubernetesClient: client,
		DynamicClient:    dynamicClient,
		DiscoveryClient:  client.Discovery(),
		Context:          context.Background(),
	}
	return NewK8sResourceHandler(context.Background(), k8s, nil, nil, "test-cluster")
}
