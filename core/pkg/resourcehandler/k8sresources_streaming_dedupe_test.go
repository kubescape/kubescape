package resourcehandler

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// TestCollectAndStreamBatches_DeduplicatesResourceServedAtSeveralVersions pins
// the bug: unlike pullResources (see
// TestPullResourcesDeduplicatesResourceServedAtSeveralVersions), the streaming
// collector never calls dedupeServedVersionAliases, so a single object served
// under two API versions is collected and reported twice on large/streaming
// scans.
func TestCollectAndStreamBatches_DeduplicatesResourceServedAtSeveralVersions(t *testing.T) {
	const uid = "11111111-1111-1111-1111-111111111111"
	alpha := schema.GroupVersionResource{Group: "agents.x-k8s.io", Version: "v1alpha1", Resource: "sandboxes"}
	beta := schema.GroupVersionResource{Group: "agents.x-k8s.io", Version: "v1beta1", Resource: "sandboxes"}

	// One Sandbox, returned by both served versions as a real CRD does.
	served := map[schema.GroupVersionResource]*unstructured.Unstructured{
		alpha: servedResource("agents.x-k8s.io/v1alpha1", "Sandbox", "agents", "alpha-sandbox", uid),
		beta:  servedResource("agents.x-k8s.io/v1beta1", "Sandbox", "agents", "alpha-sandbox", uid),
	}
	listKinds := map[schema.GroupVersionResource]string{alpha: "CustomResourceList", beta: "CustomResourceList"}
	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds)
	dynamicClient.PrependReactor("list", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		list := &unstructured.UnstructuredList{}
		if object, ok := served[action.GetResource()]; ok {
			list.Items = []unstructured.Unstructured{*object}
		}
		return true, list, nil
	})

	handler := &K8sResourceHandler{k8s: &k8sinterface.KubernetesApi{
		KubernetesClient: fakeclientset.NewClientset(),
		DynamicClient:    dynamicClient,
		DiscoveryClient:  agentRuntimeDiscovery(),
	}}
	resolver, discoveryFailures := newDiscoveryResourceResolver(handler.k8s.DiscoveryClient)
	require.Empty(t, discoveryFailures)

	namespaced := true
	queryable := QueryableResources{
		k8sinterface.GroupVersionResourceToString(&alpha): {GroupVersionResourceTriplet: k8sinterface.GroupVersionResourceToString(&alpha), Namespaced: &namespaced},
		k8sinterface.GroupVersionResourceToString(&beta):  {GroupVersionResourceTriplet: k8sinterface.GroupVersionResourceToString(&beta), Namespaced: &namespaced},
	}

	ctx := context.Background()
	scanInfo, session := streamingTestSession(ctx)
	batches := make(chan *cautils.ResourceBatch, 4)

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
	close(batches)

	total := 0
	for batch := range batches {
		total += len(batch.AllResources)
	}

	assert.Equal(t, 1, total, "one Sandbox served at two API versions must be streamed once, not once per served version")
}
