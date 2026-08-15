package resourcehandler

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

func TestAddNamespaceResourceCounts_AccumulatesResourceSets(t *testing.T) {
	counts := make(map[string]int)

	addNamespaceResourceCounts(context.Background(), map[string]workloadinterface.IMetadata{
		"deployment-a": newNamespaceCountResource("apps/v1", "Deployment", "deployment-a", "team-a"),
	}, counts, nil)
	addNamespaceResourceCounts(context.Background(), map[string]workloadinterface.IMetadata{
		"service-a": newNamespaceCountResource("v1", "Service", "service-a", "team-a"),
		"service-b": newNamespaceCountResource("v1", "Service", "service-b", "team-b"),
	}, counts, nil)

	assert.Equal(t, map[string]int{"team-a": 2, "team-b": 1}, counts)
}

func TestCollectAndStreamBatches_DeduplicatesSingleResourceNamespaceCount(t *testing.T) {
	ctx := context.Background()
	pods := testPodList("standalone-pod", "team-a")
	handler := newHandlerWithReactor(t, func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, pods, nil
	})
	scanInfo, session := streamingTestSession(ctx)
	session.SingleResourceScan = workloadinterface.NewWorkloadObj(pods.Items[0].Object)

	namespaced := true
	const podsGVR = "/v1/pods"
	queryable := QueryableResources{
		podsGVR: {
			GroupVersionResourceTriplet: podsGVR,
			Namespaced:                  &namespaced,
		},
	}
	batches := make(chan *cautils.ResourceBatch, 2)

	err := handler.collectAndStreamBatches(
		ctx,
		queryable,
		&EmptySelector{},
		session,
		scanInfo,
		cautils.ExternalResources{},
		batches,
		resourceResolver(defaultResourceResolver),
	)

	require.NoError(t, err)
	require.NotNil(t, session.Metadata.ContextMetadata.ClusterContextMetadata)
	assert.Equal(t, map[string]int{"team-a": 1}, session.Metadata.ContextMetadata.ClusterContextMetadata.MapNamespaceToNumberOfResources)

	require.Len(t, batches, 2)
	resident := <-batches
	namespace := <-batches
	resourceID := session.SingleResourceScan.GetID()
	assert.Contains(t, resident.AllResources, resourceID)
	assert.Contains(t, namespace.AllResources, resourceID)
}

func newNamespaceCountResource(apiVersion, kind, name, namespace string) workloadinterface.IMetadata {
	return workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
		},
	})
}
