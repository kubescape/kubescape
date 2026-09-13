package partitionstore

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_ConcurrentReadsAfterSeal(t *testing.T) {
	for _, backend := range []string{"memory", "disk"} {
		t.Run(backend, func(t *testing.T) {
			var store Store
			var err error
			if backend == "memory" {
				store = NewMemoryStore()
			} else {
				store, err = NewDiskStore()
				require.NoError(t, err)
			}
			defer store.Close()

			ctx := context.Background()
			numNamespaces := 10
			require.NoError(t, store.BeginGVR(ctx, "v1/pods"))
			for i := range numNamespaces {
				ns := fmt.Sprintf("ns-%d", i)
				require.NoError(t, store.Put(ctx, ns, createTestObject(fmt.Sprintf("pod-%d", i), ns, "Pod")))
			}
			require.NoError(t, store.CommitGVR(ctx, "v1/pods"))
			require.NoError(t, store.Seal(ctx))

			var wg sync.WaitGroup
			numGoroutines := 10
			for g := range numGoroutines {
				wg.Add(1)
				go func(idx int) {
					defer wg.Done()
					ns := fmt.Sprintf("ns-%d", idx%numNamespaces)
					batch, err := store.LoadBatch(ctx, ns)
					assert.NoError(t, err)
					assert.NotNil(t, batch)
					_ = store.Namespaces()
					_ = store.NamespaceCounts()
					_ = store.TotalResources()
				}(g)
			}
			wg.Wait()
		})
	}
}

func TestStore_ConcurrentOperationsAndClose(t *testing.T) {
	for _, backend := range []string{"memory", "disk"} {
		t.Run(backend, func(t *testing.T) {
			var store Store
			var err error
			if backend == "memory" {
				store = NewMemoryStore()
			} else {
				store, err = NewDiskStore()
				require.NoError(t, err)
			}

			ctx := context.Background()
			var wg sync.WaitGroup

			started := make(chan struct{})
			var once sync.Once

			// Goroutine 1: active caller attempting transactions
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range 100 {
					gvr := fmt.Sprintf("v1/res-%d", i)
					if err := store.BeginGVR(ctx, gvr); err != nil {
						return
					}
					once.Do(func() { close(started) })
					_ = store.Put(ctx, "ns-race", createTestObject(fmt.Sprintf("r-%d", i), "ns-race", "Pod"))
					if i%2 == 0 {
						_ = store.CommitGVR(ctx, gvr)
					} else {
						_ = store.RollbackGVR(ctx, gvr)
					}
				}
			}()

			// Goroutine 2: caller attempting to read/inspect
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 100 {
					_ = store.Namespaces()
					_ = store.NamespaceCounts()
					_ = store.TotalResources()
					_, _ = store.LoadBatch(ctx, "ns-race")
				}
			}()

			// Goroutine 3: caller closing the store mid-flight
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-started
				_ = store.Close()
			}()

			wg.Wait()
			// Calling close again after everything should be safe
			assert.NoError(t, store.Close())
		})
	}
}
