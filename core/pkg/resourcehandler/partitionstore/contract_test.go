package partitionstore

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestObject(name, namespace, kind string) workloadinterface.IMetadata {
	return objectsenvelopes.NewObject(map[string]any{
		"apiVersion": "v1",
		"kind":       kind,
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
			"uid":       fmt.Sprintf("uid-%s-%s", namespace, name),
			"labels": map[string]any{
				"app": "test-app",
			},
			"annotations": map[string]any{
				"secret-key": "super-sensitive-token-do-not-leak",
			},
		},
		"spec": map[string]any{
			"sensitivePayload": "secret-value-12345",
		},
	})
}

func TestMemoryStore_Contract(t *testing.T) {
	runStoreContractTests(t, func(t *testing.T) Store {
		store := NewMemoryStore()
		t.Cleanup(func() { _ = store.Close() })
		return store
	})
}

func TestMemoryStore_PurgeOnLoadOption(t *testing.T) {
	store := NewMemoryStore(WithPurgeOnLoad(true))
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	pod := createTestObject("pod-1", "ns-a", "Pod")
	require.NoError(t, store.BeginGVR(ctx, "v1/pods"))
	require.NoError(t, store.Put(ctx, "ns-a", pod))
	require.NoError(t, store.CommitGVR(ctx, "v1/pods"))
	require.NoError(t, store.Seal(ctx))

	// First load succeeds and purges
	batch, err := store.LoadBatch(ctx, "ns-a")
	require.NoError(t, err)
	assert.Len(t, batch.AllResources, 1)

	// Second load fails with ErrNamespaceNotFound because it was purged
	_, err = store.LoadBatch(ctx, "ns-a")
	assert.ErrorIs(t, err, ErrNamespaceNotFound)
}

func TestDiskStore_Contract(t *testing.T) {
	runStoreContractTests(t, func(t *testing.T) Store {
		store, err := NewDiskStore()
		require.NoError(t, err)
		t.Cleanup(func() { _ = store.Close() })
		return store
	})
}

func runStoreContractTests(t *testing.T, storeFactory func(t *testing.T) Store) {
	t.Run("CommitLifecycleAndBatchRetrieval", func(t *testing.T) {
		s := storeFactory(t)
		ctx := context.Background()

		pod1 := createTestObject("pod-1", "ns-a", "Pod")
		pod2 := createTestObject("pod-2", "ns-b", "Pod")
		dep1 := createTestObject("dep-1", "ns-a", "Deployment")

		// Ingest GVR 1
		require.NoError(t, s.BeginGVR(ctx, "v1/pods"))
		require.NoError(t, s.Put(ctx, "ns-a", pod1))
		require.NoError(t, s.Put(ctx, "ns-b", pod2))
		require.NoError(t, s.CommitGVR(ctx, "v1/pods"))

		// Ingest GVR 2
		require.NoError(t, s.BeginGVR(ctx, "apps/v1/deployments"))
		require.NoError(t, s.Put(ctx, "ns-a", dep1))
		require.NoError(t, s.CommitGVR(ctx, "apps/v1/deployments"))

		// Seal
		require.NoError(t, s.Seal(ctx))

		// Check metadata
		assert.Equal(t, []string{"ns-a", "ns-b"}, s.Namespaces())
		assert.Equal(t, map[string]int{"ns-a": 2, "ns-b": 1}, s.NamespaceCounts())
		assert.Equal(t, 3, s.TotalResources())

		// Load ns-a
		batchA, err := s.LoadBatch(ctx, "ns-a")
		require.NoError(t, err)
		assert.Equal(t, "ns-a", batchA.Scope)
		assert.Len(t, batchA.AllResources, 2)
		assert.Len(t, batchA.K8SResources["v1/pods"], 1)
		assert.Len(t, batchA.K8SResources["apps/v1/deployments"], 1)
		assert.Equal(t, "pod-1", batchA.AllResources[pod1.GetID()].GetName())
		assert.Equal(t, "dep-1", batchA.AllResources[dep1.GetID()].GetName())

		// Non-destructive by default: verify loading ns-a a second time works
		batchA2, err := s.LoadBatch(ctx, "ns-a")
		require.NoError(t, err)
		assert.Len(t, batchA2.AllResources, 2)

		// Load ns-b
		batchB, err := s.LoadBatch(ctx, "ns-b")
		require.NoError(t, err)
		assert.Equal(t, "ns-b", batchB.Scope)
		assert.Len(t, batchB.AllResources, 1)
		assert.Equal(t, "pod-2", batchB.AllResources[pod2.GetID()].GetName())
	})

	t.Run("RollbackDiscardsStagedObjects", func(t *testing.T) {
		s := storeFactory(t)
		ctx := context.Background()

		pod := createTestObject("pod-1", "ns-a", "Pod")

		require.NoError(t, s.BeginGVR(ctx, "v1/pods"))
		require.NoError(t, s.Put(ctx, "ns-a", pod))
		require.NoError(t, s.RollbackGVR(ctx, "v1/pods"))

		require.NoError(t, s.Seal(ctx))
		assert.Empty(t, s.Namespaces())
		assert.Empty(t, s.NamespaceCounts())
		assert.Zero(t, s.TotalResources())

		_, err := s.LoadBatch(ctx, "ns-a")
		assert.ErrorIs(t, err, ErrNamespaceNotFound)
	})

	t.Run("MultiGVRIsolationAcrossRollback", func(t *testing.T) {
		s := storeFactory(t)
		ctx := context.Background()

		pod := createTestObject("pod-1", "ns-a", "Pod")
		badConfig := createTestObject("bad-cfg", "ns-a", "ConfigMap")
		service := createTestObject("svc-1", "ns-a", "Service")

		// Commit pods
		require.NoError(t, s.BeginGVR(ctx, "v1/pods"))
		require.NoError(t, s.Put(ctx, "ns-a", pod))
		require.NoError(t, s.CommitGVR(ctx, "v1/pods"))

		// Rollback configmaps
		require.NoError(t, s.BeginGVR(ctx, "v1/configmaps"))
		require.NoError(t, s.Put(ctx, "ns-a", badConfig))
		require.NoError(t, s.RollbackGVR(ctx, "v1/configmaps"))

		// Commit services
		require.NoError(t, s.BeginGVR(ctx, "v1/services"))
		require.NoError(t, s.Put(ctx, "ns-a", service))
		require.NoError(t, s.CommitGVR(ctx, "v1/services"))

		require.NoError(t, s.Seal(ctx))

		batch, err := s.LoadBatch(ctx, "ns-a")
		require.NoError(t, err)
		assert.Len(t, batch.AllResources, 2)
		assert.Contains(t, batch.AllResources, pod.GetID())
		assert.Contains(t, batch.AllResources, service.GetID())
		assert.NotContains(t, batch.AllResources, badConfig.GetID())
		assert.Equal(t, 2, s.TotalResources())
	})

	t.Run("RetryReplacementContinuationToken", func(t *testing.T) {
		s := storeFactory(t)
		ctx := context.Background()

		oldPod := createTestObject("old-pod", "ns-a", "Pod")
		freshPod := createTestObject("fresh-pod", "ns-a", "Pod")

		// First try: partial read then failure
		require.NoError(t, s.BeginGVR(ctx, "v1/pods"))
		require.NoError(t, s.Put(ctx, "ns-a", oldPod))
		require.NoError(t, s.RollbackGVR(ctx, "v1/pods"))

		// Retry with fresh continuation
		require.NoError(t, s.BeginGVR(ctx, "v1/pods"))
		require.NoError(t, s.Put(ctx, "ns-a", freshPod))
		require.NoError(t, s.CommitGVR(ctx, "v1/pods"))

		require.NoError(t, s.Seal(ctx))

		batch, err := s.LoadBatch(ctx, "ns-a")
		require.NoError(t, err)
		assert.Len(t, batch.AllResources, 1)
		assert.Equal(t, "fresh-pod", batch.AllResources[freshPod.GetID()].GetName())
	})

	t.Run("StateMachineEnforcement", func(t *testing.T) {
		s := storeFactory(t)
		ctx := context.Background()
		pod := createTestObject("pod-1", "ns-a", "Pod")

		// Put without BeginGVR
		assert.ErrorIs(t, s.Put(ctx, "ns-a", pod), ErrNoActiveGVR)

		// BeginGVR
		require.NoError(t, s.BeginGVR(ctx, "v1/pods"))

		// BeginGVR again while active
		assert.ErrorIs(t, s.BeginGVR(ctx, "v1/pods"), ErrGVRAlreadyActive)

		// Mismatched commit
		assert.ErrorIs(t, s.CommitGVR(ctx, "v1/services"), ErrMismatchedGVR)

		// Mismatched rollback
		assert.ErrorIs(t, s.RollbackGVR(ctx, "v1/services"), ErrMismatchedGVR)

		// LoadBatch before Seal
		_, err := s.LoadBatch(ctx, "ns-a")
		assert.ErrorIs(t, err, ErrStoreNotSealed)

		// Commit and Seal
		require.NoError(t, s.CommitGVR(ctx, "v1/pods"))
		require.NoError(t, s.Seal(ctx))

		// Put after Seal
		assert.ErrorIs(t, s.Put(ctx, "ns-a", pod), ErrStoreSealed)
		assert.ErrorIs(t, s.BeginGVR(ctx, "v1/services"), ErrStoreSealed)

		// Operations after Close
		require.NoError(t, s.Close())
		assert.ErrorIs(t, s.BeginGVR(ctx, "v1/pods"), ErrStoreClosed)
		assert.ErrorIs(t, s.Put(ctx, "ns-a", pod), ErrStoreClosed)
		assert.ErrorIs(t, s.CommitGVR(ctx, "v1/pods"), ErrStoreClosed)
		assert.ErrorIs(t, s.RollbackGVR(ctx, "v1/pods"), ErrStoreClosed)
		assert.ErrorIs(t, s.Seal(ctx), ErrStoreClosed)
		_, err = s.LoadBatch(ctx, "ns-a")
		assert.ErrorIs(t, err, ErrStoreClosed)
		assert.ErrorIs(t, s.PurgeNamespace("ns-a"), ErrStoreClosed)
	})

	t.Run("ContextCancellation", func(t *testing.T) {
		s := storeFactory(t)
		pod := createTestObject("pod-1", "ns-a", "Pod")

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		assert.ErrorIs(t, s.BeginGVR(ctx, "v1/pods"), context.Canceled)

		// With active GVR and cancelled context
		require.NoError(t, s.BeginGVR(context.Background(), "v1/pods"))
		assert.ErrorIs(t, s.Put(ctx, "ns-a", pod), context.Canceled)
		require.NoError(t, s.RollbackGVR(context.Background(), "v1/pods"))

		// Commit, seal and test LoadBatch with cancelled context
		require.NoError(t, s.BeginGVR(context.Background(), "v1/pods"))
		require.NoError(t, s.Put(context.Background(), "ns-a", pod))
		require.NoError(t, s.CommitGVR(context.Background(), "v1/pods"))
		require.NoError(t, s.Seal(context.Background()))

		_, err := s.LoadBatch(ctx, "ns-a")
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("PurgeNamespaceAndPurgeOnLoad", func(t *testing.T) {
		s := storeFactory(t)
		ctx := context.Background()

		pod := createTestObject("pod-1", "ns-a", "Pod")
		require.NoError(t, s.BeginGVR(ctx, "v1/pods"))
		require.NoError(t, s.Put(ctx, "ns-a", pod))
		require.NoError(t, s.CommitGVR(ctx, "v1/pods"))
		require.NoError(t, s.Seal(ctx))

		require.NoError(t, s.PurgeNamespace("ns-a"))
		_, err := s.LoadBatch(ctx, "ns-a")
		assert.ErrorIs(t, err, ErrNamespaceNotFound)
	})

	t.Run("ErrorRedactionNoSensitiveData", func(t *testing.T) {
		s := storeFactory(t)
		pod := createTestObject("pod-1", "ns-a", "Pod")

		err := s.Put(context.Background(), "ns-a", pod)
		require.Error(t, err)
		assert.False(t, strings.Contains(err.Error(), "secret-key"))
		assert.False(t, strings.Contains(err.Error(), "super-sensitive-token"))
		assert.False(t, strings.Contains(err.Error(), "secret-value-12345"))
	})

	t.Run("IntegerPreservationRoundTrip", func(t *testing.T) {
		s := storeFactory(t)
		ctx := context.Background()

		const (
			smallInt = int64(3)
			largeInt = int64(9007199254740993) // 2^53 + 1, precision-loss threshold for float64
			zeroInt  = int64(0)
			negInt   = int64(-42)
			floatVal = float64(3.14)
		)

		obj := objectsenvelopes.NewObject(map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]any{
				"name":      "int-test-pod",
				"namespace": "ns-num",
			},
			"spec": map[string]any{
				"replicas": smallInt,
				"largeInt": largeInt,
				"zeroInt":  zeroInt,
				"negInt":   negInt,
				"score":    floatVal,
			},
		})

		require.NoError(t, s.BeginGVR(ctx, "v1/pods"))
		require.NoError(t, s.Put(ctx, "ns-num", obj))
		require.NoError(t, s.CommitGVR(ctx, "v1/pods"))
		require.NoError(t, s.Seal(ctx))

		batch, err := s.LoadBatch(ctx, "ns-num")
		require.NoError(t, err)
		require.Len(t, batch.AllResources, 1)

		loadedObj := batch.AllResources[obj.GetID()]
		spec, ok := loadedObj.GetObject()["spec"].(map[string]any)
		require.True(t, ok, "spec should be map[string]any")

		// Verify integer preservation (type int64 and exact value)
		assert.IsType(t, int64(0), spec["replicas"])
		assert.Equal(t, smallInt, spec["replicas"])

		assert.IsType(t, int64(0), spec["largeInt"])
		assert.Equal(t, largeInt, spec["largeInt"])

		assert.IsType(t, int64(0), spec["zeroInt"])
		assert.Equal(t, zeroInt, spec["zeroInt"])

		assert.IsType(t, int64(0), spec["negInt"])
		assert.Equal(t, negInt, spec["negInt"])

		// Verify float is preserved
		assert.IsType(t, float64(0), spec["score"])
		assert.Equal(t, floatVal, spec["score"])
	})

	t.Run("LoadMutateLoadParity", func(t *testing.T) {
		s := storeFactory(t)
		ctx := context.Background()

		originalObj := createTestObject("pod-parity", "ns-parity", "Pod")

		require.NoError(t, s.BeginGVR(ctx, "v1/pods"))
		require.NoError(t, s.Put(ctx, "ns-parity", originalObj))
		require.NoError(t, s.CommitGVR(ctx, "v1/pods"))
		require.NoError(t, s.Seal(ctx))

		// First load: obtain batch1
		batch1, err := s.LoadBatch(ctx, "ns-parity")
		require.NoError(t, err)
		require.Len(t, batch1.AllResources, 1)

		loaded1 := batch1.AllResources[originalObj.GetID()]
		assert.Equal(t, "secret-value-12345", loaded1.GetObject()["spec"].(map[string]any)["sensitivePayload"])

		// Mutate batch1 in-place
		spec1 := loaded1.GetObject()["spec"].(map[string]any)
		spec1["sensitivePayload"] = "MUTATED-PAYLOAD-VALUE"
		spec1["newKey"] = "unexpected"
		meta1 := loaded1.GetObject()["metadata"].(map[string]any)
		meta1["labels"].(map[string]any)["mutated"] = "true"

		// Second load: obtain batch2
		batch2, err := s.LoadBatch(ctx, "ns-parity")
		require.NoError(t, err)
		require.Len(t, batch2.AllResources, 1)

		loaded2 := batch2.AllResources[originalObj.GetID()]
		spec2 := loaded2.GetObject()["spec"].(map[string]any)
		meta2 := loaded2.GetObject()["metadata"].(map[string]any)

		// Verify batch2 was NOT mutated and retains original committed values
		assert.Equal(t, "secret-value-12345", spec2["sensitivePayload"], "subsequent LoadBatch must not observe mutations to earlier batch")
		assert.NotContains(t, spec2, "newKey")
		assert.NotContains(t, meta2["labels"].(map[string]any), "mutated")
	})

	t.Run("LongValidGVRContract", func(t *testing.T) {
		s := storeFactory(t)
		ctx := context.Background()

		// Valid Kubernetes API group formed of three 63-byte DNS labels (191 bytes) + version (8) + resource (15) = 216 bytes
		group := fmt.Sprintf("%s.%s.%s", strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63))
		longGVR := fmt.Sprintf("%s/v1alpha1/customresources", group)
		require.Greater(t, len(longGVR), 200, "GVR length should exceed 200 bytes")

		crdObj := createTestObject("crd-1", "ns-crd", "CustomResource")

		require.NoError(t, s.BeginGVR(ctx, longGVR))
		require.NoError(t, s.Put(ctx, "ns-crd", crdObj))
		require.NoError(t, s.CommitGVR(ctx, longGVR))
		require.NoError(t, s.Seal(ctx))

		batch, err := s.LoadBatch(ctx, "ns-crd")
		require.NoError(t, err)
		require.Len(t, batch.AllResources, 1)
		assert.Contains(t, batch.K8SResources, longGVR)
		assert.Equal(t, []string{crdObj.GetID()}, batch.K8SResources[longGVR])
		assert.Equal(t, "crd-1", batch.AllResources[crdObj.GetID()].GetName())
	})
}
