package partitionstore

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type accountingStoreFactory struct {
	name string
	new  func(t *testing.T, opts ...Option) Store
}

func accountingStoreFactories() []accountingStoreFactory {
	return []accountingStoreFactory{
		{
			name: "memory",
			new: func(t *testing.T, opts ...Option) Store {
				t.Helper()
				store := NewMemoryStore(opts...)
				t.Cleanup(func() { _ = store.Close() })
				return store
			},
		},
		{
			name: "disk",
			new: func(t *testing.T, opts ...Option) Store {
				t.Helper()
				store, err := NewDiskStore(append([]Option{WithBaseDir(t.TempDir())}, opts...)...)
				require.NoError(t, err)
				t.Cleanup(func() { _ = store.Close() })
				return store
			},
		},
	}
}

func commitAccountingObjects(t *testing.T, store Store, gvr string, objectsByNamespace map[string]int) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, store.BeginGVR(ctx, gvr))
	for namespace, count := range objectsByNamespace {
		for i := 0; i < count; i++ {
			obj := createTestObject(fmt.Sprintf("%s-%d", gvr, i), namespace, "Pod")
			require.NoError(t, store.Put(ctx, namespace, obj))
		}
	}
	require.NoError(t, store.CommitGVR(ctx, gvr))
}

func assertStoreAccounting(t *testing.T, store Store, namespaces []string, counts map[string]int, total int) {
	t.Helper()
	assert.ElementsMatch(t, namespaces, store.Namespaces())
	assert.Equal(t, counts, store.NamespaceCounts())
	assert.Equal(t, total, store.TotalResources())
}

func TestPurgeNamespace_RemovesResourceAccounting(t *testing.T) {
	for _, factory := range accountingStoreFactories() {
		t.Run(factory.name, func(t *testing.T) {
			store := factory.new(t)
			commitAccountingObjects(t, store, "v1/pods", map[string]int{
				"prod":    3,
				"staging": 2,
			})
			require.NoError(t, store.Seal(context.Background()))
			assertStoreAccounting(t, store,
				[]string{"prod", "staging"},
				map[string]int{"prod": 3, "staging": 2},
				5,
			)

			require.NoError(t, store.PurgeNamespace("prod"))

			assertStoreAccounting(t, store,
				[]string{"staging"},
				map[string]int{"staging": 2},
				2,
			)
			_, err := store.LoadBatch(context.Background(), "prod")
			assert.ErrorIs(t, err, ErrNamespaceNotFound)
			batch, err := store.LoadBatch(context.Background(), "staging")
			require.NoError(t, err)
			assert.Len(t, batch.AllResources, 2)
		})
	}
}

func TestPurgeNamespace_OnlySubtractsPurgedNamespaceAcrossGVRs(t *testing.T) {
	for _, factory := range accountingStoreFactories() {
		t.Run(factory.name, func(t *testing.T) {
			store := factory.new(t)
			commitAccountingObjects(t, store, "v1/pods", map[string]int{
				"alpha": 2,
				"beta":  1,
				"gamma": 1,
			})
			commitAccountingObjects(t, store, "apps/v1/deployments", map[string]int{
				"alpha": 3,
				"beta":  2,
			})
			commitAccountingObjects(t, store, "batch/v1/jobs", map[string]int{
				"alpha": 1,
				"gamma": 4,
			})
			require.NoError(t, store.Seal(context.Background()))
			assertStoreAccounting(t, store,
				[]string{"alpha", "beta", "gamma"},
				map[string]int{"alpha": 6, "beta": 3, "gamma": 5},
				14,
			)

			require.NoError(t, store.PurgeNamespace("alpha"))

			assertStoreAccounting(t, store,
				[]string{"beta", "gamma"},
				map[string]int{"beta": 3, "gamma": 5},
				8,
			)
		})
	}
}

func TestPurgeNamespace_IsIdempotentForAccounting(t *testing.T) {
	for _, factory := range accountingStoreFactories() {
		t.Run(factory.name, func(t *testing.T) {
			store := factory.new(t)
			commitAccountingObjects(t, store, "v1/pods", map[string]int{"prod": 4})
			require.NoError(t, store.Seal(context.Background()))

			require.NoError(t, store.PurgeNamespace("prod"))
			require.NoError(t, store.PurgeNamespace("prod"))
			require.NoError(t, store.PurgeNamespace("prod"))

			assertStoreAccounting(t, store, []string{}, map[string]int{}, 0)
		})
	}
}

func TestPurgeNamespace_UnknownNamespaceDoesNotChangeAccounting(t *testing.T) {
	for _, factory := range accountingStoreFactories() {
		t.Run(factory.name, func(t *testing.T) {
			store := factory.new(t)
			commitAccountingObjects(t, store, "v1/pods", map[string]int{"prod": 2})
			require.NoError(t, store.Seal(context.Background()))

			require.NoError(t, store.PurgeNamespace("does-not-exist"))

			assertStoreAccounting(t, store,
				[]string{"prod"},
				map[string]int{"prod": 2},
				2,
			)
		})
	}
}

func TestPurgeNamespace_AllNamespacesReachZeroExactly(t *testing.T) {
	for _, factory := range accountingStoreFactories() {
		t.Run(factory.name, func(t *testing.T) {
			store := factory.new(t)
			commitAccountingObjects(t, store, "v1/pods", map[string]int{
				"a": 1,
				"b": 2,
				"c": 3,
				"d": 4,
			})
			require.NoError(t, store.Seal(context.Background()))

			for _, namespace := range []string{"c", "a", "d", "b"} {
				before := store.TotalResources()
				count := store.NamespaceCounts()[namespace]
				require.NoError(t, store.PurgeNamespace(namespace))
				assert.Equal(t, before-count, store.TotalResources())
				assert.NotContains(t, store.NamespaceCounts(), namespace)
				assert.NotContains(t, store.Namespaces(), namespace)
			}

			assertStoreAccounting(t, store, []string{}, map[string]int{}, 0)
		})
	}
}

func TestPurgeNamespace_BeforeSealAllowsFreshNamespaceAccounting(t *testing.T) {
	for _, factory := range accountingStoreFactories() {
		t.Run(factory.name, func(t *testing.T) {
			store := factory.new(t)
			commitAccountingObjects(t, store, "v1/pods", map[string]int{
				"reused": 5,
				"stable": 1,
			})

			require.NoError(t, store.PurgeNamespace("reused"))
			assert.Equal(t, 1, store.TotalResources())

			commitAccountingObjects(t, store, "apps/v1/deployments", map[string]int{
				"reused": 2,
			})
			require.NoError(t, store.Seal(context.Background()))

			assertStoreAccounting(t, store,
				[]string{"reused", "stable"},
				map[string]int{"reused": 2, "stable": 1},
				3,
			)
			batch, err := store.LoadBatch(context.Background(), "reused")
			require.NoError(t, err)
			assert.Len(t, batch.AllResources, 2)
			assert.Empty(t, batch.K8SResources["v1/pods"])
			assert.Len(t, batch.K8SResources["apps/v1/deployments"], 2)
		})
	}
}

func TestPurgeOnLoad_RemovesAccountingAfterSuccessfulLoad(t *testing.T) {
	for _, factory := range accountingStoreFactories() {
		t.Run(factory.name, func(t *testing.T) {
			store := factory.new(t, WithPurgeOnLoad(true))
			commitAccountingObjects(t, store, "v1/pods", map[string]int{
				"first":  3,
				"second": 2,
			})
			require.NoError(t, store.Seal(context.Background()))

			batch, err := store.LoadBatch(context.Background(), "first")
			require.NoError(t, err)
			assert.Len(t, batch.AllResources, 3)
			assertStoreAccounting(t, store,
				[]string{"second"},
				map[string]int{"second": 2},
				2,
			)

			batch, err = store.LoadBatch(context.Background(), "second")
			require.NoError(t, err)
			assert.Len(t, batch.AllResources, 2)
			assertStoreAccounting(t, store, []string{}, map[string]int{}, 0)
		})
	}
}

func TestPurgeOnLoad_MissingAndRepeatedLoadsDoNotUnderflow(t *testing.T) {
	for _, factory := range accountingStoreFactories() {
		t.Run(factory.name, func(t *testing.T) {
			store := factory.new(t, WithPurgeOnLoad(true))
			commitAccountingObjects(t, store, "v1/pods", map[string]int{"prod": 1})
			require.NoError(t, store.Seal(context.Background()))

			_, err := store.LoadBatch(context.Background(), "missing")
			assert.ErrorIs(t, err, ErrNamespaceNotFound)
			assert.Equal(t, 1, store.TotalResources())

			_, err = store.LoadBatch(context.Background(), "prod")
			require.NoError(t, err)
			assert.Zero(t, store.TotalResources())

			_, err = store.LoadBatch(context.Background(), "prod")
			assert.ErrorIs(t, err, ErrNamespaceNotFound)
			assert.Zero(t, store.TotalResources())
		})
	}
}

func TestPurgeOnLoad_CancelledLoadKeepsAccountingAndPartition(t *testing.T) {
	for _, factory := range accountingStoreFactories() {
		t.Run(factory.name, func(t *testing.T) {
			store := factory.new(t, WithPurgeOnLoad(true))
			commitAccountingObjects(t, store, "v1/pods", map[string]int{"prod": 2})
			require.NoError(t, store.Seal(context.Background()))

			cancelled, cancel := context.WithCancel(context.Background())
			cancel()
			_, err := store.LoadBatch(cancelled, "prod")
			assert.ErrorIs(t, err, context.Canceled)
			assertStoreAccounting(t, store,
				[]string{"prod"},
				map[string]int{"prod": 2},
				2,
			)

			batch, err := store.LoadBatch(context.Background(), "prod")
			require.NoError(t, err)
			assert.Len(t, batch.AllResources, 2)
			assertStoreAccounting(t, store, []string{}, map[string]int{}, 0)
		})
	}
}

func TestNamespaceCounts_ReturnedMapCannotCorruptPurgeAccounting(t *testing.T) {
	for _, factory := range accountingStoreFactories() {
		t.Run(factory.name, func(t *testing.T) {
			store := factory.new(t)
			commitAccountingObjects(t, store, "v1/pods", map[string]int{
				"prod":    3,
				"staging": 2,
			})
			require.NoError(t, store.Seal(context.Background()))

			snapshot := store.NamespaceCounts()
			snapshot["prod"] = 1000
			delete(snapshot, "staging")
			snapshot["invented"] = 500

			require.NoError(t, store.PurgeNamespace("prod"))
			assertStoreAccounting(t, store,
				[]string{"staging"},
				map[string]int{"staging": 2},
				2,
			)
		})
	}
}

func TestPurgeNamespace_ConcurrentIdempotentCallsDoNotUnderflow(t *testing.T) {
	for _, factory := range accountingStoreFactories() {
		t.Run(factory.name, func(t *testing.T) {
			store := factory.new(t)
			commitAccountingObjects(t, store, "v1/pods", map[string]int{
				"target": 10,
				"keep":   4,
			})
			require.NoError(t, store.Seal(context.Background()))

			const workers = 32
			var wg sync.WaitGroup
			errs := make(chan error, workers)
			for i := 0; i < workers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					errs <- store.PurgeNamespace("target")
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				require.NoError(t, err)
			}

			assertStoreAccounting(t, store,
				[]string{"keep"},
				map[string]int{"keep": 4},
				4,
			)
		})
	}
}

func TestPurgeNamespace_UnicodeAndPunctuationNamespacesUpdateAccounting(t *testing.T) {
	for _, factory := range accountingStoreFactories() {
		t.Run(factory.name, func(t *testing.T) {
			store := factory.new(t)
			commitAccountingObjects(t, store, "v1/pods", map[string]int{
				"team-a.prod": 2,
				"研发":          1,
			})
			require.NoError(t, store.Seal(context.Background()))

			require.NoError(t, store.PurgeNamespace("研发"))

			assertStoreAccounting(t, store,
				[]string{"team-a.prod"},
				map[string]int{"team-a.prod": 2},
				2,
			)
		})
	}
}

func TestPurgeNamespace_DuringActiveTransactionCountsOnlyCommittedData(t *testing.T) {
	for _, factory := range accountingStoreFactories() {
		t.Run(factory.name, func(t *testing.T) {
			store := factory.new(t)
			commitAccountingObjects(t, store, "v1/pods", map[string]int{
				"reused": 3,
				"stable": 2,
			})

			ctx := context.Background()
			require.NoError(t, store.BeginGVR(ctx, "apps/v1/deployments"))
			for i := 0; i < 4; i++ {
				obj := createTestObject(fmt.Sprintf("deployment-%d", i), "reused", "Deployment")
				require.NoError(t, store.Put(ctx, "reused", obj))
			}

			// Staged resources are not committed accounting yet. Purging here
			// removes only the three committed pods. The four staged
			// deployments become the namespace's fresh count at commit.
			require.NoError(t, store.PurgeNamespace("reused"))
			assert.Equal(t, 2, store.TotalResources())

			require.NoError(t, store.CommitGVR(ctx, "apps/v1/deployments"))
			require.NoError(t, store.Seal(ctx))
			assertStoreAccounting(t, store,
				[]string{"reused", "stable"},
				map[string]int{"reused": 4, "stable": 2},
				6,
			)

			batch, err := store.LoadBatch(ctx, "reused")
			require.NoError(t, err)
			assert.Len(t, batch.AllResources, 4)
			assert.Len(t, batch.K8SResources["apps/v1/deployments"], 4)
			assert.Empty(t, batch.K8SResources["v1/pods"])
		})
	}
}

func TestPurgeOnLoad_TracksEachNamespaceIndependentlyAcrossGVRs(t *testing.T) {
	for _, factory := range accountingStoreFactories() {
		t.Run(factory.name, func(t *testing.T) {
			store := factory.new(t, WithPurgeOnLoad(true))
			commitAccountingObjects(t, store, "v1/pods", map[string]int{
				"alpha": 2,
				"beta":  1,
				"gamma": 3,
			})
			commitAccountingObjects(t, store, "v1/services", map[string]int{
				"alpha": 1,
				"gamma": 2,
			})
			require.NoError(t, store.Seal(context.Background()))
			assertStoreAccounting(t, store,
				[]string{"alpha", "beta", "gamma"},
				map[string]int{"alpha": 3, "beta": 1, "gamma": 5},
				9,
			)

			alpha, err := store.LoadBatch(context.Background(), "alpha")
			require.NoError(t, err)
			assert.Len(t, alpha.AllResources, 3)
			assertStoreAccounting(t, store,
				[]string{"beta", "gamma"},
				map[string]int{"beta": 1, "gamma": 5},
				6,
			)

			gamma, err := store.LoadBatch(context.Background(), "gamma")
			require.NoError(t, err)
			assert.Len(t, gamma.AllResources, 5)
			assertStoreAccounting(t, store,
				[]string{"beta"},
				map[string]int{"beta": 1},
				1,
			)

			beta, err := store.LoadBatch(context.Background(), "beta")
			require.NoError(t, err)
			assert.Len(t, beta.AllResources, 1)
			assertStoreAccounting(t, store, nil, map[string]int{}, 0)
		})
	}
}

func TestPurgeNamespace_PreservesAccountingAfterFailedLoad(t *testing.T) {
	for _, factory := range accountingStoreFactories() {
		t.Run(factory.name, func(t *testing.T) {
			store := factory.new(t)
			commitAccountingObjects(t, store, "v1/pods", map[string]int{"prod": 2})
			require.NoError(t, store.Seal(context.Background()))

			_, err := store.LoadBatch(context.Background(), "missing")
			assert.ErrorIs(t, err, ErrNamespaceNotFound)
			assertStoreAccounting(t, store,
				[]string{"prod"},
				map[string]int{"prod": 2},
				2,
			)

			require.NoError(t, store.PurgeNamespace("prod"))
			assertStoreAccounting(t, store, nil, map[string]int{}, 0)
		})
	}
}
