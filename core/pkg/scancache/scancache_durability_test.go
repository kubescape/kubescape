package scancache

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func cacheVerdict(controlID string) resourcesresults.ResourceAssociatedControl {
	return resourcesresults.ResourceAssociatedControl{ControlID: controlID}
}

func cachePath(dir string) string {
	return filepath.Join(dir, cacheFileName)
}

func readDiskCacheForTest(t *testing.T, dir string) diskCache {
	t.Helper()
	raw, err := os.ReadFile(cachePath(dir))
	require.NoError(t, err)
	var persisted diskCache
	require.NoError(t, json.Unmarshal(raw, &persisted))
	return persisted
}

func TestLoadNullEntriesRemainsWritable(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(cachePath(dir), []byte(`{"version":"v1","entries":null}`), 0o600))

	store, err := Load(dir, "v1")
	require.NoError(t, err)
	require.NotNil(t, store.data)

	assert.NotPanics(t, func() {
		store.Put("C-1", "resource-1", "hash-1", cacheVerdict("C-1"))
	})
	require.NoError(t, store.Flush())

	loaded, err := Load(dir, "v1")
	require.NoError(t, err)
	verdict, ok := loaded.Get("C-1", "resource-1", "hash-1")
	assert.True(t, ok)
	assert.Equal(t, "C-1", verdict.ControlID)
}

func TestPutRepairsNilMapsOnManuallyConstructedStore(t *testing.T) {
	store := &Store{
		path:    cachePath(t.TempDir()),
		version: "v1",
	}

	assert.NotPanics(t, func() {
		store.Put("C-1", "resource-1", "hash-1", cacheVerdict("C-1"))
	})
	assert.Len(t, store.data, 1)
	assert.Len(t, store.pending, 1)
	assert.True(t, store.dirty)
}

func TestFlushCreatesMissingCacheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "cache")
	store, err := Load(dir, "v1")
	require.NoError(t, err)
	store.Put("C-1", "resource-1", "hash-1", cacheVerdict("C-1"))

	require.NoError(t, store.Flush())
	info, err := os.Stat(cachePath(dir))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestFlushReplacesMalformedGeneration(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(cachePath(dir), []byte(`{"version":"v1","entries":`), 0o600))

	store, err := Load(dir, "v1")
	require.NoError(t, err)
	store.Put("C-1", "resource-1", "hash-1", cacheVerdict("C-1"))
	require.NoError(t, store.Flush())

	persisted := readDiskCacheForTest(t, dir)
	assert.Equal(t, "v1", persisted.Version)
	assert.Len(t, persisted.Entries, 1)
}

func TestIndependentStoresMergePendingEntries(t *testing.T) {
	dir := t.TempDir()
	first, err := Load(dir, "v1")
	require.NoError(t, err)
	second, err := Load(dir, "v1")
	require.NoError(t, err)

	first.Put("C-1", "resource-1", "hash-1", cacheVerdict("C-1"))
	second.Put("C-2", "resource-2", "hash-2", cacheVerdict("C-2"))
	require.NoError(t, first.Flush())
	require.NoError(t, second.Flush())

	loaded, err := Load(dir, "v1")
	require.NoError(t, err)
	firstVerdict, firstOK := loaded.Get("C-1", "resource-1", "hash-1")
	secondVerdict, secondOK := loaded.Get("C-2", "resource-2", "hash-2")
	assert.True(t, firstOK)
	assert.True(t, secondOK)
	assert.Equal(t, "C-1", firstVerdict.ControlID)
	assert.Equal(t, "C-2", secondVerdict.ControlID)
}

func TestStaleStoreDoesNotOverwriteNewerEntryItDidNotChange(t *testing.T) {
	dir := t.TempDir()
	seed, err := Load(dir, "v1")
	require.NoError(t, err)
	seed.Put("C-shared", "resource", "old-hash", cacheVerdict("old"))
	require.NoError(t, seed.Flush())

	stale, err := Load(dir, "v1")
	require.NoError(t, err)
	fresh, err := Load(dir, "v1")
	require.NoError(t, err)

	fresh.Put("C-shared", "resource", "new-hash", cacheVerdict("new"))
	require.NoError(t, fresh.Flush())
	stale.Put("C-other", "resource", "other-hash", cacheVerdict("other"))
	require.NoError(t, stale.Flush())

	loaded, err := Load(dir, "v1")
	require.NoError(t, err)
	shared, ok := loaded.Get("C-shared", "resource", "new-hash")
	assert.True(t, ok)
	assert.Equal(t, "new", shared.ControlID)
	other, ok := loaded.Get("C-other", "resource", "other-hash")
	assert.True(t, ok)
	assert.Equal(t, "other", other.ControlID)
}

func TestPendingEntryWinsSameKeyConflict(t *testing.T) {
	dir := t.TempDir()
	first, err := Load(dir, "v1")
	require.NoError(t, err)
	second, err := Load(dir, "v1")
	require.NoError(t, err)

	first.Put("C-1", "resource", "first-hash", cacheVerdict("first"))
	second.Put("C-1", "resource", "second-hash", cacheVerdict("second"))
	require.NoError(t, first.Flush())
	require.NoError(t, second.Flush())

	loaded, err := Load(dir, "v1")
	require.NoError(t, err)
	verdict, ok := loaded.Get("C-1", "resource", "second-hash")
	assert.True(t, ok)
	assert.Equal(t, "second", verdict.ControlID)
	_, oldOK := loaded.Get("C-1", "resource", "first-hash")
	assert.False(t, oldOK)
}

func TestConcurrentStoresCommitWholeMergedGeneration(t *testing.T) {
	dir := t.TempDir()
	const writers = 24
	stores := make([]*Store, writers)
	for i := range stores {
		store, err := Load(dir, "v1")
		require.NoError(t, err)
		controlID := fmt.Sprintf("C-%02d", i)
		store.Put(controlID, fmt.Sprintf("resource-%02d", i), fmt.Sprintf("hash-%02d", i), cacheVerdict(controlID))
		stores[i] = store
	}

	start := make(chan struct{})
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for _, store := range stores {
		wg.Add(1)
		go func(store *Store) {
			defer wg.Done()
			<-start
			errs <- store.Flush()
		}(store)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	loaded, err := Load(dir, "v1")
	require.NoError(t, err)
	for i := 0; i < writers; i++ {
		controlID := fmt.Sprintf("C-%02d", i)
		verdict, ok := loaded.Get(controlID, fmt.Sprintf("resource-%02d", i), fmt.Sprintf("hash-%02d", i))
		assert.True(t, ok, controlID)
		assert.Equal(t, controlID, verdict.ControlID)
	}
	assert.Len(t, loaded.data, writers)
}

func TestDifferentVersionStartsFreshGeneration(t *testing.T) {
	dir := t.TempDir()
	oldStore, err := Load(dir, "v1")
	require.NoError(t, err)
	oldStore.Put("C-old", "resource", "old-hash", cacheVerdict("old"))
	require.NoError(t, oldStore.Flush())

	newStore, err := Load(dir, "v2")
	require.NoError(t, err)
	newStore.Put("C-new", "resource", "new-hash", cacheVerdict("new"))
	require.NoError(t, newStore.Flush())

	persisted := readDiskCacheForTest(t, dir)
	assert.Equal(t, "v2", persisted.Version)
	assert.NotContains(t, persisted.Entries, "C-old|resource")
	assert.Contains(t, persisted.Entries, "C-new|resource")
}

func TestFlushClearsOnlyCommittedPendingEntries(t *testing.T) {
	dir := t.TempDir()
	store, err := Load(dir, "v1")
	require.NoError(t, err)
	store.Put("C-1", "resource", "hash", cacheVerdict("C-1"))

	require.NoError(t, store.Flush())
	assert.False(t, store.dirty)
	assert.Empty(t, store.pending)
	assert.Len(t, store.data, 1)
}

func TestAtomicFlushNeverExposesPartialJSON(t *testing.T) {
	dir := t.TempDir()
	seed, err := Load(dir, "v1")
	require.NoError(t, err)
	seed.Put("seed", "resource", "hash", cacheVerdict("seed"))
	require.NoError(t, seed.Flush())

	readerDone := make(chan struct{})
	readerErr := make(chan error, 1)
	go func() {
		defer close(readerDone)
		for i := 0; i < 500; i++ {
			raw, err := os.ReadFile(cachePath(dir))
			if err != nil {
				readerErr <- err
				return
			}
			var generation diskCache
			if err := json.Unmarshal(raw, &generation); err != nil {
				readerErr <- err
				return
			}
		}
		readerErr <- nil
	}()

	for i := 0; i < 40; i++ {
		store, err := Load(dir, "v1")
		require.NoError(t, err)
		controlID := fmt.Sprintf("C-%d", i)
		store.Put(controlID, "resource", fmt.Sprintf("hash-%d", i), cacheVerdict(controlID))
		require.NoError(t, store.Flush())
	}

	<-readerDone
	require.NoError(t, <-readerErr)
}

func TestDeleteAndFlushUseSameLock(t *testing.T) {
	dir := t.TempDir()
	store, err := Load(dir, "v1")
	require.NoError(t, err)
	store.Put("C-1", "resource", "hash", cacheVerdict("C-1"))
	require.NoError(t, store.Flush())

	require.NoError(t, Delete(dir))
	_, err = os.Stat(cachePath(dir))
	assert.True(t, os.IsNotExist(err))

	// A store that was already in memory may safely publish a new generation
	// after deletion. The important invariant is that neither operation can
	// observe or leave a partially written file.
	store.Put("C-2", "resource", "hash-2", cacheVerdict("C-2"))
	require.NoError(t, store.Flush())
	loaded, err := Load(dir, "v1")
	require.NoError(t, err)
	_, ok := loaded.Get("C-2", "resource", "hash-2")
	assert.True(t, ok)
}
