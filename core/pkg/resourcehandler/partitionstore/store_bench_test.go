package partitionstore

import (
	"context"
	"fmt"
	"testing"
)

func BenchmarkDiskStore_20kObjects(b *testing.B) {
	ctx := context.Background()
	numNamespaces := 50
	podsPerNS := 400 // 50 * 400 = 20,000 objects

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		store, err := NewDiskStore()
		if err != nil {
			b.Fatalf("failed to create disk store: %v", err)
		}

		if err := store.BeginGVR(ctx, "v1/pods"); err != nil {
			b.Fatalf("failed BeginGVR: %v", err)
		}

		for nsIdx := range numNamespaces {
			ns := fmt.Sprintf("bench-ns-%d", nsIdx)
			for i := range podsPerNS {
				obj := createTestObject(fmt.Sprintf("pod-%d", i), ns, "Pod")
				if err := store.Put(ctx, ns, obj); err != nil {
					b.Fatalf("failed Put: %v", err)
				}
			}
		}

		if err := store.CommitGVR(ctx, "v1/pods"); err != nil {
			b.Fatalf("failed CommitGVR: %v", err)
		}

		if err := store.Seal(ctx); err != nil {
			b.Fatalf("failed Seal: %v", err)
		}

		// Replay all batches
		for _, ns := range store.Namespaces() {
			batch, err := store.LoadBatch(ctx, ns)
			if err != nil {
				b.Fatalf("failed LoadBatch: %v", err)
			}
			if len(batch.AllResources) != podsPerNS {
				b.Fatalf("expected %d resources in namespace %s, got %d", podsPerNS, ns, len(batch.AllResources))
			}
		}

		_ = store.Close()
	}
}

func BenchmarkDiskStore_1kNamespaces_LRUThrashing(b *testing.B) {
	ctx := context.Background()
	numNamespaces := 1000 // 1,000 namespaces on a 64-FD pool
	numGVRs := 3

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		store, err := NewDiskStore() // default MaxOpenFiles = 64
		if err != nil {
			b.Fatalf("failed to create disk store: %v", err)
		}

		for g := range numGVRs {
			gvr := fmt.Sprintf("v1/kind-%d", g)
			if err := store.BeginGVR(ctx, gvr); err != nil {
				b.Fatalf("failed BeginGVR: %v", err)
			}

			// In each GVR, write to all 1,000 namespaces, forcing heavy LRU eviction and reopening
			for nsIdx := range numNamespaces {
				ns := fmt.Sprintf("ns-%04d", nsIdx)
				obj := createTestObject(fmt.Sprintf("res-%d", g), ns, "Workload")
				if err := store.Put(ctx, ns, obj); err != nil {
					b.Fatalf("failed Put: %v", err)
				}
			}

			if err := store.CommitGVR(ctx, gvr); err != nil {
				b.Fatalf("failed CommitGVR: %v", err)
			}
		}

		if err := store.Seal(ctx); err != nil {
			b.Fatalf("failed Seal: %v", err)
		}

		if len(store.Namespaces()) != numNamespaces {
			b.Fatalf("expected %d namespaces, got %d", numNamespaces, len(store.Namespaces()))
		}

		_ = store.Close()
	}
}
