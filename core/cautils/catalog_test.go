package cautils

import (
	"fmt"
	"sync"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapResourceCatalog_CRUD(t *testing.T) {
	catalog := NewMapResourceCatalog()
	assert.Equal(t, 0, catalog.Len())
	assert.Empty(t, catalog.ListIDs())

	pod1 := mustWorkload(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-1","namespace":"default"}}`)
	pod2 := mustWorkload(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-2","namespace":"default"}}`)

	// Add
	catalog.Add(pod1)
	assert.Equal(t, 1, catalog.Len())

	// Get existing
	got, ok := catalog.Get(pod1.GetID())
	require.True(t, ok)
	assert.Equal(t, pod1.GetID(), got.GetID())

	// Get missing
	_, ok = catalog.Get("non-existent")
	assert.False(t, ok)

	// AddAll
	catalog.AddAll(map[string]workloadinterface.IMetadata{
		pod2.GetID(): pod2,
	})
	assert.Equal(t, 2, catalog.Len())

	ids := catalog.ListIDs()
	assert.Len(t, ids, 2)
	assert.Contains(t, ids, pod1.GetID())
	assert.Contains(t, ids, pod2.GetID())

	// Remove
	catalog.Remove(pod1.GetID())
	assert.Equal(t, 1, catalog.Len())
	_, ok = catalog.Get(pod1.GetID())
	assert.False(t, ok)
}

func TestMapResourceCatalog_NilSafety(t *testing.T) {
	catalog := NewMapResourceCatalog()
	// Adding nil should not panic or increment count
	catalog.Add(nil)
	assert.Equal(t, 0, catalog.Len())

	// AddAll with nil map or nil values
	catalog.AddAll(nil)
	assert.Equal(t, 0, catalog.Len())
	catalog.AddAll(map[string]workloadinterface.IMetadata{"empty": nil})
	assert.Equal(t, 0, catalog.Len())
}

func TestMapResourceCatalog_ForEach(t *testing.T) {
	catalog := NewMapResourceCatalog()
	pod1 := mustWorkload(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-1","namespace":"default"}}`)
	pod2 := mustWorkload(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-2","namespace":"default"}}`)
	catalog.Add(pod1)
	catalog.Add(pod2)

	// Full traversal
	visited := make(map[string]bool)
	catalog.ForEach(func(id string, resource workloadinterface.IMetadata) bool {
		visited[id] = true
		return true
	})
	assert.Len(t, visited, 2)

	// Early termination
	count := 0
	catalog.ForEach(func(id string, resource workloadinterface.IMetadata) bool {
		count++
		return false // stop immediately
	})
	assert.Equal(t, 1, count)
}

func TestMapResourceCatalog_SnapshotIsolation(t *testing.T) {
	catalog := NewMapResourceCatalog()
	pod1 := mustWorkload(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-1","namespace":"default"}}`)
	catalog.Add(pod1)

	snapshot := catalog.All()
	assert.Len(t, snapshot, 1)

	// Adding to catalog should not alter previously returned snapshot
	pod2 := mustWorkload(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-2","namespace":"default"}}`)
	catalog.Add(pod2)

	assert.Equal(t, 2, catalog.Len())
	assert.Len(t, snapshot, 1)
}

func TestMapResourceCatalog_BackingMapSync(t *testing.T) {
	backingMap := make(map[string]workloadinterface.IMetadata)
	catalog := NewMapResourceCatalog(backingMap)

	pod1 := mustWorkload(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-1","namespace":"default"}}`)
	catalog.Add(pod1)

	// The backing map must reflect the addition
	assert.Contains(t, backingMap, pod1.GetID())

	// Mutating the backing map directly must be visible via catalog
	pod2 := mustWorkload(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-2","namespace":"default"}}`)
	backingMap[pod2.GetID()] = pod2

	got, ok := catalog.Get(pod2.GetID())
	require.True(t, ok)
	assert.Equal(t, pod2.GetID(), got.GetID())
	assert.Equal(t, 2, catalog.Len())

	// Removing via catalog reflects in backing map
	catalog.Remove(pod1.GetID())
	assert.NotContains(t, backingMap, pod1.GetID())
}

func TestMapResourceCatalog_ConcurrentAccess(t *testing.T) {
	catalog := NewMapResourceCatalog()
	const numGoroutines = 10
	const numOps = 200

	// Pre-generate workloads so we do not call require (t.FailNow) from child goroutines
	workloads := make([][]workloadinterface.IMetadata, numGoroutines)
	for g := 0; g < numGoroutines; g++ {
		workloads[g] = make([]workloadinterface.IMetadata, numOps)
		for i := 0; i < numOps; i++ {
			workloads[g][i] = mustWorkload(t, fmt.Sprintf(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-%d-%d","namespace":"default"}}`, g, i))
		}
	}

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2)

	// Writers
	for g := 0; g < numGoroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < numOps; i++ {
				catalog.Add(workloads[gid][i])
			}
		}(g)
	}

	// Readers
	for g := 0; g < numGoroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < numOps; i++ {
				_ = catalog.Len()
				_ = catalog.ListIDs()
				_ = catalog.All()
				catalog.ForEach(func(id string, resource workloadinterface.IMetadata) bool {
					return true
				})
			}
		}()
	}

	wg.Wait()
	assert.Equal(t, numGoroutines*numOps, catalog.Len())
}

func TestOPASessionObj_SetCatalog_PreservesMapResourceCatalog(t *testing.T) {
	session := &OPASessionObj{
		AllResources: map[string]workloadinterface.IMetadata{
			"old-res": mustWorkload(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"old-pod","namespace":"default"}}`),
		},
	}

	// Initialize catalog lazily backed by initial AllResources
	cat1 := session.GetCatalog()
	require.Equal(t, 1, cat1.Len())

	// Call SetCatalog with a new MapResourceCatalog
	newPod := mustWorkload(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"new-pod","namespace":"prod"}}`)
	newMap := map[string]workloadinterface.IMetadata{
		newPod.GetID(): newPod,
	}
	cat2 := NewMapResourceCatalog(newMap)
	session.SetCatalog(cat2)

	// Subsequent GetCatalog must return cat2 and not replace it with an old catalog
	catAfter := session.GetCatalog()
	assert.Equal(t, cat2, catAfter)
	assert.Equal(t, 1, catAfter.Len())

	// GetResource must find newPod and not old-res
	got, ok := session.GetResource(newPod.GetID())
	assert.True(t, ok)
	assert.Equal(t, newPod.GetID(), got.GetID())

	_, oldOk := session.GetResource("old-res")
	assert.False(t, oldOk)

	// AllResources must be synchronized with cat2's backing map
	assert.Contains(t, session.AllResources, newPod.GetID())
	assert.NotContains(t, session.AllResources, "old-res")
}

func TestOPASessionObj_GetCatalog_AllResourcesReassignmentRewrap(t *testing.T) {
	pod1 := mustWorkload(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-1","namespace":"default"}}`)
	session := &OPASessionObj{
		AllResources: map[string]workloadinterface.IMetadata{
			pod1.GetID(): pod1,
		},
	}

	// First GetCatalog creates a catalog wrapping initial AllResources
	cat1 := session.GetCatalog()
	require.Equal(t, 1, cat1.Len())
	_, ok := cat1.Get(pod1.GetID())
	require.True(t, ok)

	// Direct reassignment of AllResources (simulating handlerpullresources.go or anonymizer)
	pod2 := mustWorkload(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-2","namespace":"prod"}}`)
	session.AllResources = map[string]workloadinterface.IMetadata{
		pod2.GetID(): pod2,
	}

	// Subsequent GetCatalog must detect the reassigned map pointer and re-wrap it
	cat2 := session.GetCatalog()
	require.Equal(t, 1, cat2.Len())
	got, ok := cat2.Get(pod2.GetID())
	require.True(t, ok)
	assert.Equal(t, pod2.GetID(), got.GetID())
	_, oldOk := cat2.Get(pod1.GetID())
	assert.False(t, oldOk)
}

func TestOPASessionObj_SetCatalog_TypedNilMapResourceCatalog(t *testing.T) {
	session := &OPASessionObj{
		AllResources: map[string]workloadinterface.IMetadata{},
	}
	var nilMC *MapResourceCatalog = nil
	session.SetCatalog(nilMC)

	// GetCatalog must not panic and must self-heal to a valid catalog
	cat := session.GetCatalog()
	require.NotNil(t, cat)
	assert.Equal(t, 0, cat.Len())
}
