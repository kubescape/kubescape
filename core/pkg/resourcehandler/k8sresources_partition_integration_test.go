package resourcehandler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resourcehandler/partitionstore"
	"github.com/kubescape/rbac-utils/rbacscanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/fake"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestCollectAndStreamBatches_CleansUpSpillDirectoryOnSuccess(t *testing.T) {
	ctx := context.Background()
	pods := testPodList("pod-1", "team-a")
	handler := newHandlerWithReactor(t, func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, pods, nil
	})

	var createdRootDir string
	handler.SetStoreFactory(func() (partitionstore.Store, error) {
		store, err := partitionstore.NewDiskStore()
		if err != nil {
			return nil, err
		}
		// Wrap store to capture created root dir
		return &rootDirCaptureStore{Store: store, onInit: func(dir string) {
			createdRootDir = dir
		}}, nil
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
	close(batches)

	// Drain batches
	for range batches {
	}

	require.NotEmpty(t, createdRootDir, "a DiskStore root dir should have been initialized")
	_, statErr := os.Stat(createdRootDir)
	assert.True(t, os.IsNotExist(statErr), "spill directory %s must be completely removed on success", createdRootDir)
}

func TestCollectAndStreamBatches_CleansUpSpillDirectoryOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var createdRootDir string
	pods := testPodList("pod-1", "team-a")
	handler := newHandlerWithReactor(t, func(k8stesting.Action) (bool, runtime.Object, error) {
		cancel() // Cancel during reactor execution
		return true, pods, nil
	})

	handler.SetStoreFactory(func() (partitionstore.Store, error) {
		store, err := partitionstore.NewDiskStore()
		if err != nil {
			return nil, err
		}
		return &rootDirCaptureStore{Store: store, onInit: func(dir string) {
			createdRootDir = dir
		}}, nil
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
	assert.ErrorIs(t, err, context.Canceled)

	require.NotEmpty(t, createdRootDir)
	_, statErr := os.Stat(createdRootDir)
	assert.True(t, os.IsNotExist(statErr), "spill directory %s must be cleaned up on context cancellation", createdRootDir)
}

func TestCollectAndStreamBatches_RollbackOnGVRFailurePreservesCommitted(t *testing.T) {
	ctx := context.Background()
	pods := testPodList("surviving-pod", "team-a")
	handler := newHandlerWithReactor(t, func(action k8stesting.Action) (bool, runtime.Object, error) {
		switch action.GetResource().Resource {
		case "pods":
			return true, pods, nil
		case "somecrd":
			return true, nil, fmt.Errorf("simulated fatal failure on failed GVR")
		default:
			t.Fatalf("unexpected resource: %s", action.GetResource().Resource)
			return true, nil, nil
		}
	})

	scanInfo, session := streamingTestSession(ctx)
	namespaced := true
	const (
		podsGVR   = "/v1/pods"
		failedGVR = "/v1/somecrd"
	)
	queryable := QueryableResources{
		podsGVR: {
			GroupVersionResourceTriplet: podsGVR,
			Namespaced:                  &namespaced,
		},
		failedGVR: {
			GroupVersionResourceTriplet: failedGVR,
			Namespaced:                  &namespaced,
		},
	}
	batches := make(chan *cautils.ResourceBatch, 4)

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
	require.NoError(t, err, "non-fatal whole-GVR failure alongside a successful GVR should not abort scan")
	close(batches)

	resident := <-batches
	assert.Equal(t, cautils.ClusterScope, resident.Scope)

	batch := <-batches
	assert.Equal(t, "team-a", batch.Scope)
	assert.Contains(t, batch.K8SResources, podsGVR)
	assert.NotContains(t, batch.K8SResources, failedGVR, "rolled back GVR should have no traces in committed partition")
}

func TestCollectAndStreamBatches_LoadBatchFailureFailsClosed(t *testing.T) {
	ctx := context.Background()
	pods := testPodList("pod-1", "team-a")
	handler := newHandlerWithReactor(t, func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, pods, nil
	})

	// Inject a store where LoadBatch fails
	handler.SetStoreFactory(func() (partitionstore.Store, error) {
		baseStore := partitionstore.NewMemoryStore()
		return &failingLoadBatchStore{Store: baseStore, failErr: errors.New("simulated disk corruption on LoadBatch")}, nil
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
	require.Error(t, err)
	assert.ErrorContains(t, err, "failed to load partition for namespace team-a")
	assert.ErrorContains(t, err, "simulated disk corruption on LoadBatch")
}

func TestCollectAndStreamBatches_ClusterScopedSingleResourceScanNotDoubleCounted(t *testing.T) {
	ctx := context.Background()
	crbs := &unstructured.UnstructuredList{
		Object: map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBindingList"},
		Items: []unstructured.Unstructured{
			{Object: map[string]any{
				"apiVersion": "rbac.authorization.k8s.io/v1",
				"kind":       "ClusterRoleBinding",
				"metadata": map[string]any{
					"name": "crb-1",
				},
			}},
		},
	}
	handler := newHandlerWithReactor(t, func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, crbs, nil
	})

	scanInfo, session := streamingTestSession(ctx)
	// SingleResourceScan is a ClusterRoleBinding (cluster-scoped)
	session.SingleResourceScan = workloadinterface.NewWorkloadObj(crbs.Items[0].Object)

	clusterScoped := false
	const crbGVR = "rbac.authorization.k8s.io/v1/clusterrolebindings"
	queryable := QueryableResources{
		crbGVR: {
			GroupVersionResourceTriplet: crbGVR,
			Namespaced:                  &clusterScoped,
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
	close(batches)

	resident := <-batches
	assert.Equal(t, cautils.ClusterScope, resident.Scope)
	// ClusterRoleBinding should be in resident AllResources
	assert.Contains(t, resident.AllResources, session.SingleResourceScan.GetID())
	require.Contains(t, resident.K8SResources, crbGVR)
	assert.Len(t, resident.K8SResources[crbGVR], 1)
	// Namespace resource counts map should not contain cluster-scoped resources
	assert.Empty(t, session.Metadata.ContextMetadata.ClusterContextMetadata.MapNamespaceToNumberOfResources)
}

func TestCollectAndStreamBatches_NamespacedSingleResourceScanExcludedByKindFilterReturnsError(t *testing.T) {
	ctx := context.Background()
	pods := testPodList("standalone-pod", "team-a")
	handler := newHandlerWithReactor(t, func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, pods, nil
	})
	scanInfo, session := streamingTestSession(ctx)
	session.SingleResourceScan = workloadinterface.NewWorkloadObj(pods.Items[0].Object)
	scanInfo.ExcludeKinds = "Pod"

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
	require.Error(t, err)
	assert.ErrorContains(t, err, "kind filter excludes the explicitly requested scan target")
}

// Helpers for integration test

type rootDirCaptureStore struct {
	partitionstore.Store
	onInit func(string)
}

func (s *rootDirCaptureStore) BeginGVR(ctx context.Context, gvr string) error {
	if ds, ok := s.Store.(*partitionstore.DiskStore); ok && s.onInit != nil {
		s.onInit(ds.RootDir())
		s.onInit = nil
	}
	return s.Store.BeginGVR(ctx, gvr)
}

type failingLoadBatchStore struct {
	partitionstore.Store
	failErr error
}

func (f *failingLoadBatchStore) LoadBatch(ctx context.Context, namespace string) (*cautils.ResourceBatch, error) {
	return nil, f.failErr
}

func TestCollectAndStreamBatches_StorePutFailureRollsBackGVRAndExcludesPartialData(t *testing.T) {
	ctx := context.Background()
	twoPods := &unstructured.UnstructuredList{
		Object: map[string]any{"apiVersion": "v1", "kind": "PodList"},
		Items: []unstructured.Unstructured{
			{Object: map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "pod-1", "namespace": "team-a"}}},
			{Object: map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "pod-2", "namespace": "team-a"}}},
		},
	}
	somecrds := &unstructured.UnstructuredList{
		Object: map[string]any{"apiVersion": "v1", "kind": "SomeCRDList"},
		Items: []unstructured.Unstructured{
			{Object: map[string]any{"apiVersion": "v1", "kind": "SomeCRD", "metadata": map[string]any{"name": "crd-1", "namespace": "team-a"}}},
		},
	}

	handler := newHandlerWithReactor(t, func(action k8stesting.Action) (bool, runtime.Object, error) {
		switch action.GetResource().Resource {
		case "pods":
			return true, twoPods, nil
		case "somecrd":
			return true, somecrds, nil
		default:
			t.Fatalf("unexpected resource: %s", action.GetResource().Resource)
			return true, nil, nil
		}
	})

	failingStore := &failingPutStore{
		Store:     partitionstore.NewMemoryStore(),
		failOnPut: 2, // Fail on the second pod
		failErr:   errors.New("simulated disk failure on Put"),
	}
	handler.SetStoreFactory(func() (partitionstore.Store, error) {
		return failingStore, nil
	})

	scanInfo, session := streamingTestSession(ctx)
	namespaced := true
	const (
		podsGVR    = "/v1/pods"
		somecrdGVR = "/v1/somecrd"
	)
	queryable := QueryableResources{
		podsGVR: {
			GroupVersionResourceTriplet: podsGVR,
			Namespaced:                  &namespaced,
		},
		somecrdGVR: {
			GroupVersionResourceTriplet: somecrdGVR,
			Namespaced:                  &namespaced,
		},
	}
	batches := make(chan *cautils.ResourceBatch, 4)

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
	close(batches)

	assert.Contains(t, failingStore.rollbackGVRs, podsGVR, "GVR with failed write must be rolled back")
	assert.Empty(t, session.PartialGVRFailures, "failed write must not surface as partial coverage")
	assert.Contains(t, session.InfoMap, podsGVR, "rolled back GVR should be recorded in InfoMap")

	resident := <-batches
	assert.Equal(t, cautils.ClusterScope, resident.Scope)

	batch := <-batches
	assert.Equal(t, "team-a", batch.Scope)
	assert.Contains(t, batch.K8SResources, somecrdGVR)
	assert.NotContains(t, batch.K8SResources, podsGVR, "rolled back pods must not be in committed partition")
	assert.Equal(t, map[string]int{"team-a": 1}, session.Metadata.ContextMetadata.ClusterContextMetadata.MapNamespaceToNumberOfResources)
}

type failingPutStore struct {
	partitionstore.Store
	putCount     int
	failOnPut    int
	failErr      error
	rollbackGVRs []string
}

func (f *failingPutStore) BeginGVR(ctx context.Context, gvr string) error {
	f.putCount = 0
	return f.Store.BeginGVR(ctx, gvr)
}

func (f *failingPutStore) Put(ctx context.Context, namespace string, obj workloadinterface.IMetadata) error {
	f.putCount++
	if f.putCount == f.failOnPut {
		return f.failErr
	}
	return f.Store.Put(ctx, namespace, obj)
}

func (f *failingPutStore) RollbackGVR(ctx context.Context, gvr string) error {
	f.rollbackGVRs = append(f.rollbackGVRs, gvr)
	return f.Store.RollbackGVR(ctx, gvr)
}

type failingRollbackStore struct {
	partitionstore.Store
	failOnPut     bool
	putErr        error
	failRollback  bool
	rollbackErr   error
	beginGVRCalls []string
	rollbackCalls []string
}

func (s *failingRollbackStore) BeginGVR(ctx context.Context, gvr string) error {
	s.beginGVRCalls = append(s.beginGVRCalls, gvr)
	return s.Store.BeginGVR(ctx, gvr)
}

func (s *failingRollbackStore) Put(ctx context.Context, namespace string, obj workloadinterface.IMetadata) error {
	if s.failOnPut {
		return s.putErr
	}
	return s.Store.Put(ctx, namespace, obj)
}

func (s *failingRollbackStore) RollbackGVR(ctx context.Context, gvr string) error {
	s.rollbackCalls = append(s.rollbackCalls, gvr)
	if s.failRollback {
		return s.rollbackErr
	}
	return s.Store.RollbackGVR(ctx, gvr)
}

func TestCollectAndStreamBatches_SinkWriteFailureRollbackFailureAbortsCollection(t *testing.T) {
	ctx := context.Background()
	pods := &unstructured.UnstructuredList{
		Object: map[string]any{"apiVersion": "v1", "kind": "PodList"},
		Items: []unstructured.Unstructured{
			{Object: map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "pod-1", "namespace": "team-a"}}},
		},
	}
	services := &unstructured.UnstructuredList{
		Object: map[string]any{"apiVersion": "v1", "kind": "ServiceList"},
		Items: []unstructured.Unstructured{
			{Object: map[string]any{"apiVersion": "v1", "kind": "Service", "metadata": map[string]any{"name": "svc-1", "namespace": "team-a"}}},
		},
	}

	handler := newHandlerWithReactor(t, func(action k8stesting.Action) (bool, runtime.Object, error) {
		switch action.GetResource().Resource {
		case "pods":
			return true, pods, nil
		case "services":
			return true, services, nil
		default:
			t.Fatalf("unexpected resource: %s", action.GetResource().Resource)
			return true, nil, nil
		}
	})

	putErr := errors.New("simulated disk write failure")
	rollbackErr := errors.New("simulated rollback failure")
	failingStore := &failingRollbackStore{
		Store:        partitionstore.NewMemoryStore(),
		failOnPut:    true,
		putErr:       putErr,
		failRollback: true,
		rollbackErr:  rollbackErr,
	}
	handler.SetStoreFactory(func() (partitionstore.Store, error) {
		return failingStore, nil
	})

	scanInfo, session := streamingTestSession(ctx)
	namespaced := true
	const (
		podsGVR = "/v1/pods"
		svcGVR  = "/v1/services"
	)
	queryable := QueryableResources{
		podsGVR: {
			GroupVersionResourceTriplet: podsGVR,
			Namespaced:                  &namespaced,
		},
		svcGVR: {
			GroupVersionResourceTriplet: svcGVR,
			Namespaced:                  &namespaced,
		},
	}
	batches := make(chan *cautils.ResourceBatch, 4)

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
	require.Error(t, err)
	assert.ErrorIs(t, err, putErr)
	assert.ErrorIs(t, err, rollbackErr)
	assert.Len(t, failingStore.rollbackCalls, 1, "RollbackGVR must be called once")
	assert.Len(t, failingStore.beginGVRCalls, 1, "subsequent GVR query must not begin after rollback failure")
}

func TestCollectAndStreamBatches_SelectorFailureRollbackFailureAbortsCollection(t *testing.T) {
	ctx := context.Background()
	handler := newHandlerWithReactor(t, func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("forbidden: cannot list pods")
	})

	rollbackErr := errors.New("simulated rollback failure on selector error")
	failingStore := &failingRollbackStore{
		Store:        partitionstore.NewMemoryStore(),
		failRollback: true,
		rollbackErr:  rollbackErr,
	}
	handler.SetStoreFactory(func() (partitionstore.Store, error) {
		return failingStore, nil
	})

	scanInfo, session := streamingTestSession(ctx)
	namespaced := true
	const (
		podsGVR = "/v1/pods"
		svcGVR  = "/v1/services"
	)
	queryable := QueryableResources{
		podsGVR: {
			GroupVersionResourceTriplet: podsGVR,
			Namespaced:                  &namespaced,
		},
		svcGVR: {
			GroupVersionResourceTriplet: svcGVR,
			Namespaced:                  &namespaced,
		},
	}
	batches := make(chan *cautils.ResourceBatch, 4)

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
	require.Error(t, err)
	assert.ErrorContains(t, err, "cannot list pods")
	assert.ErrorIs(t, err, rollbackErr)
	assert.Len(t, failingStore.rollbackCalls, 1, "RollbackGVR must be called once")
	assert.Len(t, failingStore.beginGVRCalls, 1, "subsequent GVR query must not begin after rollback failure")
}

func TestCollectAndStreamBatches_FallsBackToMemoryStoreWhenTempDirUnwritable(t *testing.T) {
	ctx := context.Background()
	invalidBaseDir := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(invalidBaseDir, []byte("x"), 0o600))
	t.Setenv("KUBESCAPE_SPILL_DIR", invalidBaseDir)

	pods := testPodList("pod-fallback", "team-fallback")
	// Use default newStore() with NO SetStoreFactory override
	handler := newHandlerWithReactor(t, func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, pods, nil
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
	close(batches)

	resident := <-batches
	assert.Equal(t, cautils.ClusterScope, resident.Scope)

	nsBatch := <-batches
	assert.Equal(t, "team-fallback", nsBatch.Scope)
	assert.Contains(t, nsBatch.AllResources, "/v1/team-fallback/Pod/pod-fallback")
	assert.Equal(t, map[string]int{"team-fallback": 1}, session.Metadata.ContextMetadata.ClusterContextMetadata.MapNamespaceToNumberOfResources)
}

func TestCollectAndStreamBatches_ExplicitMemoryStoreOptOut(t *testing.T) {
	ctx := context.Background()
	t.Setenv("KUBESCAPE_PARTITION_STORE", "memory")

	pods := testPodList("pod-optout", "team-optout")
	handler := newHandlerWithReactor(t, func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, pods, nil
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
	close(batches)

	resident := <-batches
	assert.Equal(t, cautils.ClusterScope, resident.Scope)

	nsBatch := <-batches
	assert.Equal(t, "team-optout", nsBatch.Scope)
	assert.Contains(t, nsBatch.AllResources, "/v1/team-optout/Pod/pod-optout")
}

func TestCollectAndStreamBatches_RbacInjectedNamespacedResourcesNotDoubleCounted(t *testing.T) {
	ctx := context.Background()
	role := &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "Role",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "reader",
			Namespace: "team-a",
		},
	}
	roleList := &unstructured.UnstructuredList{
		Object: map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleList"},
		Items: []unstructured.Unstructured{
			{Object: map[string]any{
				"apiVersion": "rbac.authorization.k8s.io/v1",
				"kind":       "Role",
				"metadata": map[string]any{
					"name":      "reader",
					"namespace": "team-a",
				},
			}},
		},
	}

	client := fakeclientset.NewSimpleClientset(role)
	dynClient := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), testGVRToListKind)
	dynClient.PrependReactor("list", "*", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, roleList, nil
	})

	k8s := &k8sinterface.KubernetesApi{
		KubernetesClient: client,
		DynamicClient:    dynClient,
		DiscoveryClient:  client.Discovery(),
		Context:          ctx,
	}
	rbacScanner := rbacscanner.NewRbacScannerFromK8sAPI(k8s, "", "test-cluster")
	rbacObjects := cautils.NewRBACObjects(rbacScanner)
	handler := NewK8sResourceHandler(ctx, k8s, nil, rbacObjects, "test-cluster")

	scanInfo, session := streamingTestSession(ctx)
	namespaced := true
	const rolesGVR = "rbac.authorization.k8s.io/v1/roles"
	queryable := QueryableResources{
		rolesGVR: {
			GroupVersionResourceTriplet: rolesGVR,
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
	close(batches)

	// Consume batches
	for range batches {
	}

	// RBAC role should only be counted ONCE in MapNamespaceToNumberOfResources, not twice
	assert.Equal(t, map[string]int{"team-a": 1}, session.Metadata.ContextMetadata.ClusterContextMetadata.MapNamespaceToNumberOfResources)
}
