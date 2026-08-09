package resourcehandler

import (
	"context"
	"fmt"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stesting "k8s.io/client-go/testing"
)

func streamingTestSession(ctx context.Context) (*cautils.ScanInfo, *cautils.OPASessionObj) {
	scanInfo := &cautils.ScanInfo{InputPatterns: []string{"/not-a-cluster-scan"}}
	return scanInfo, cautils.NewOPASessionObj(ctx, nil, nil, scanInfo, nil)
}

func testPodList(name, namespace string) *unstructured.UnstructuredList {
	return &unstructured.UnstructuredList{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "PodList",
		},
		Items: []unstructured.Unstructured{{Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]any{
				"name":      name,
				"namespace": namespace,
			},
		}}},
	}
}

func TestCollectAndStreamBatches_FailsWhenAllQueriesFail(t *testing.T) {
	ctx := context.Background()
	handler := newHandlerWithReactor(t, func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("forbidden: cannot list %s", action.GetResource().Resource)
	})
	scanInfo, session := streamingTestSession(ctx)
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
		nil,
	)

	require.ErrorContains(t, err, "failed to pull any Kubernetes resources")
	assert.ErrorContains(t, err, "forbidden")
	assert.Empty(t, batches, "an all-failed collection must not emit an empty resident batch")

	info, ok := session.InfoMap[podsGVR]
	require.True(t, ok, "the failed GVR must be available to scan coverage")
	assert.Equal(t, apis.StatusSkipped, info.InnerStatus)
	assert.Equal(t, apis.SubStatusNotEvaluated, info.SubStatus)
}

func TestCollectAndStreamBatches_IgnoresMissingOptionalResource(t *testing.T) {
	ctx := context.Background()
	handler := newHandlerWithReactor(t, func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewNotFound(schema.GroupResource{Group: "example.com", Resource: "somecrds"}, "")
	})
	scanInfo, session := streamingTestSession(ctx)
	namespaced := true
	const optionalGVR = "/v1/somecrd"
	queryable := QueryableResources{
		optionalGVR: {
			GroupVersionResourceTriplet: optionalGVR,
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
		nil,
	)

	require.NoError(t, err, "an optional CRD that is not installed must not abort the scan")
	assert.Empty(t, session.InfoMap)
	assert.Empty(t, session.PartialGVRFailures)

	require.Len(t, batches, 1)
	resident := <-batches
	assert.Equal(t, cautils.ClusterScope, resident.Scope)
	assert.Empty(t, resident.AllResources)
}

func TestCollectAndStreamBatches_RecordsWholeGVRFailureAlongsideSuccess(t *testing.T) {
	ctx := context.Background()
	handler := newHandlerWithReactor(t, func(action k8stesting.Action) (bool, runtime.Object, error) {
		switch action.GetResource().Resource {
		case "pods":
			return true, testPodList("survives", "default"), nil
		case "clusterrolebindings":
			return true, nil, fmt.Errorf("forbidden: cannot list clusterrolebindings")
		default:
			t.Fatalf("unexpected resource: %s", action.GetResource().Resource)
			return true, nil, nil
		}
	})
	scanInfo, session := streamingTestSession(ctx)
	namespaced := true
	clusterScoped := false
	const (
		podsGVR                = "/v1/pods"
		clusterRoleBindingsGVR = "rbac.authorization.k8s.io/v1/clusterrolebindings"
	)
	queryable := QueryableResources{
		podsGVR: {
			GroupVersionResourceTriplet: podsGVR,
			Namespaced:                  &namespaced,
		},
		clusterRoleBindingsGVR: {
			GroupVersionResourceTriplet: clusterRoleBindingsGVR,
			Namespaced:                  &clusterScoped,
		},
	}
	batches := make(chan *cautils.ResourceBatch, 3)

	err := handler.collectAndStreamBatches(
		ctx,
		queryable,
		&EmptySelector{},
		session,
		scanInfo,
		cautils.ExternalResources{},
		batches,
		nil,
	)

	require.NoError(t, err, "a whole-GVR failure must not discard resources from another GVR")
	info, ok := session.InfoMap[clusterRoleBindingsGVR]
	require.True(t, ok, "the failed GVR must remain visible in scan coverage")
	assert.Equal(t, apis.StatusSkipped, info.InnerStatus)
	assert.Equal(t, apis.SubStatusNotEvaluated, info.SubStatus)
	assert.Empty(t, session.PartialGVRFailures)

	require.Len(t, batches, 2)
	resident := <-batches
	defaultBatch := <-batches
	assert.Equal(t, cautils.ClusterScope, resident.Scope)
	assert.Equal(t, "default", defaultBatch.Scope)
	assert.Len(t, defaultBatch.K8SResources[podsGVR], 1)
}

// TestCollectAndStreamBatches_HostScannerDisabled_MarksControlsSkipped guards
// against the streaming collector silently dropping host-sensor controls: with
// HostScanner disabled, GetResources (the non-streaming path) records these
// controls as skipped with a pointer to the operator. The streaming collector
// must record the same InfoMap entry, or the control resolves to Passed.
func TestCollectAndStreamBatches_HostScannerDisabled_MarksControlsSkipped(t *testing.T) {
	ctx := context.Background()
	handler := newHandlerWithReactor(t, func(action k8stesting.Action) (bool, runtime.Object, error) {
		t.Fatalf("unexpected resource: %s", action.GetResource().Resource)
		return true, nil, nil
	})
	scanInfo, session := streamingTestSession(ctx)
	session.Metadata.ScanMetadata.HostScanner = false
	batches := make(chan *cautils.ResourceBatch, 1)

	err := handler.collectAndStreamBatches(
		ctx,
		QueryableResources{},
		&EmptySelector{},
		session,
		scanInfo,
		cautils.ExternalResources{"KubeletConfiguration": nil},
		batches,
		nil,
	)

	require.NoError(t, err)
	info, ok := session.InfoMap["KubeletConfiguration"]
	require.True(t, ok, "host-sensor resources must be recorded as skipped when the host scanner is disabled")
	assert.Equal(t, apis.StatusSkipped, info.InnerStatus)
	assert.Contains(t, info.InnerInfo, "Install the Kubescape operator")
}

// TestCollectAndStreamBatches_CountsNamespacedResourcesAcrossBatches guards
// against setMapNamespaceToNumOfResources being handed only the resident
// (cluster-scoped) batch: namespaced resources live in namespaceBatches, so
// counting resident.AllResources alone always yields an empty map.
func TestCollectAndStreamBatches_CountsNamespacedResourcesAcrossBatches(t *testing.T) {
	ctx := context.Background()
	twoPods := &unstructured.UnstructuredList{
		Object: map[string]any{"apiVersion": "v1", "kind": "PodList"},
		Items: []unstructured.Unstructured{
			{Object: map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "a", "namespace": "ns-a"}}},
			{Object: map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "b", "namespace": "ns-a"}}},
		},
	}
	handler := newHandlerWithReactor(t, func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, twoPods, nil
	})
	scanInfo, session := streamingTestSession(ctx)
	namespaced := true
	const podsGVR = "/v1/pods"
	queryable := QueryableResources{
		podsGVR: {
			GroupVersionResourceTriplet: podsGVR,
			Namespaced:                  &namespaced,
		},
	}
	batches := make(chan *cautils.ResourceBatch, 3)

	err := handler.collectAndStreamBatches(
		ctx,
		queryable,
		&EmptySelector{},
		session,
		scanInfo,
		cautils.ExternalResources{},
		batches,
		nil,
	)

	require.NoError(t, err)
	require.NotNil(t, session.Metadata.ContextMetadata.ClusterContextMetadata)
	assert.Equal(t, map[string]int{"ns-a": 2}, session.Metadata.ContextMetadata.ClusterContextMetadata.MapNamespaceToNumberOfResources)
}

func TestCollectAndStreamBatches_RecordsPartialSelectorFailure(t *testing.T) {
	ctx := context.Background()
	handler := newHandlerWithReactor(t, func(action k8stesting.Action) (bool, runtime.Object, error) {
		listAction, ok := action.(k8stesting.ListAction)
		require.True(t, ok)
		if listAction.GetListRestrictions().Fields.String() == "metadata.namespace=denied" {
			return true, nil, fmt.Errorf("forbidden: cannot list pods in denied")
		}
		return true, testPodList("survives", "allowed"), nil
	})
	scanInfo, session := streamingTestSession(ctx)
	namespaced := true
	const podsGVR = "/v1/pods"
	queryable := QueryableResources{
		podsGVR: {
			GroupVersionResourceTriplet: podsGVR,
			Namespaced:                  &namespaced,
		},
	}
	selectors := &staticFieldSelector{selectors: []string{
		"metadata.namespace=allowed",
		"metadata.namespace=denied",
	}}
	batches := make(chan *cautils.ResourceBatch, 3)

	err := handler.collectAndStreamBatches(
		ctx,
		queryable,
		selectors,
		session,
		scanInfo,
		cautils.ExternalResources{},
		batches,
		nil,
	)

	require.NoError(t, err, "a partial selector failure must not abort a usable scan")
	assert.NotContains(t, session.InfoMap, podsGVR, "a partially collected GVR is not wholly skipped")
	require.Len(t, session.PartialGVRFailures, 1)
	assert.Equal(t, podsGVR, session.PartialGVRFailures[0].GVR)
	assert.Equal(t, "metadata.namespace=denied", session.PartialGVRFailures[0].Selector)
	assert.Contains(t, session.PartialGVRFailures[0].Error, "forbidden")

	require.Len(t, batches, 2)
	resident := <-batches
	allowed := <-batches
	assert.Equal(t, cautils.ClusterScope, resident.Scope)
	assert.Equal(t, "allowed", allowed.Scope)
	assert.Len(t, allowed.AllResources, 1, "resources from successful selectors must survive")
}

func TestCollectAndStreamBatches_CleanSuccessHasNoFailureMetadata(t *testing.T) {
	ctx := context.Background()
	handler := newHandlerWithReactor(t, func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, testPodList("clean", "default"), nil
	})
	scanInfo, session := streamingTestSession(ctx)
	namespaced := true
	const podsGVR = "/v1/pods"
	queryable := QueryableResources{
		podsGVR: {
			GroupVersionResourceTriplet: podsGVR,
			Namespaced:                  &namespaced,
		},
	}
	batches := make(chan *cautils.ResourceBatch, 3)

	err := handler.collectAndStreamBatches(
		ctx,
		queryable,
		&EmptySelector{},
		session,
		scanInfo,
		cautils.ExternalResources{},
		batches,
		nil,
	)

	require.NoError(t, err)
	assert.Empty(t, session.InfoMap)
	assert.Empty(t, session.PartialGVRFailures)

	require.Len(t, batches, 2)
	resident := <-batches
	defaultBatch := <-batches
	assert.Equal(t, cautils.ClusterScope, resident.Scope)
	assert.Equal(t, "default", defaultBatch.Scope)
	assert.Len(t, defaultBatch.K8SResources[podsGVR], 1)
}

// TestCollectAndStreamBatches_LabelSelectorReachesStreamingPath verifies that
// scanInfo.LabelSelector is forwarded to listOptions.LabelSelector in the
// collectAndStreamBatches code path, which is exercised by StreamResourcesBatches
// and is separate from the pullResources eager-collection path.
func TestCollectAndStreamBatches_LabelSelectorReachesStreamingPath(t *testing.T) {
	ctx := context.Background()

	var (
		podsSelectorCaptured bool
		capturedPodsLabel    string
	)
	handler := newHandlerWithReactor(t, func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.GetResource().Resource != "pods" {
			return true, &unstructured.UnstructuredList{}, nil
		}
		listAction, ok := action.(k8stesting.ListAction)
		require.True(t, ok)
		podsSelectorCaptured = true
		capturedPodsLabel = listAction.GetListRestrictions().Labels.String()
		return true, testPodList("web", "default"), nil
	})

	scanInfo, session := streamingTestSession(ctx)
	scanInfo.LabelSelector = "app=nginx"

	namespaced := true
	const podsGVR = "/v1/pods"
	queryable := QueryableResources{
		podsGVR: {
			GroupVersionResourceTriplet: podsGVR,
			Namespaced:                  &namespaced,
		},
	}
	batches := make(chan *cautils.ResourceBatch, 3)

	err := handler.collectAndStreamBatches(
		ctx,
		queryable,
		&EmptySelector{},
		session,
		scanInfo,
		cautils.ExternalResources{},
		batches,
		nil,
	)

	require.NoError(t, err)
	require.True(t, podsSelectorCaptured, "expected at least one pods LIST action to be intercepted")
	assert.Equal(t, "app=nginx", capturedPodsLabel,
		"label selector from scanInfo must reach listOptions.LabelSelector in the streaming path")
}
