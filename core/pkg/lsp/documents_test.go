package lsp

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDocumentStoreOpenLifecycleAndOpenID(t *testing.T) {
	store := newDocumentStore()
	path := filepath.Join(t.TempDir(), "pod.yaml")
	uri := uriFromPath(path)

	store.open(uri, path, 1, false)
	doc1, ok := store.get(path)
	require.True(t, ok)
	assert.Equal(t, uri, doc1.uri)
	assert.Equal(t, path, doc1.path)
	assert.Equal(t, int32(1), doc1.version)
	assert.False(t, doc1.dirty)
	assert.NotZero(t, doc1.openID)

	// Change document: version updates, marked dirty, openID preserved.
	ok = store.change(path, 2)
	require.True(t, ok)
	doc2, ok := store.get(path)
	require.True(t, ok)
	assert.Equal(t, int32(2), doc2.version)
	assert.True(t, doc2.dirty)
	assert.Equal(t, doc1.openID, doc2.openID)

	// Save document: dirty cleared, openID preserved.
	doc3, ok := store.saved(path)
	require.True(t, ok)
	assert.Equal(t, int32(2), doc3.version)
	assert.False(t, doc3.dirty)
	assert.Equal(t, doc1.openID, doc3.openID)

	// Close document.
	docClosed, ok := store.close(path)
	require.True(t, ok)
	assert.Equal(t, doc1.openID, docClosed.openID)

	_, ok = store.get(path)
	assert.False(t, ok)

	// Reopen the same path at version 1: must get a new distinct openID.
	store.open(uri, path, 1, false)
	docReopened, ok := store.get(path)
	require.True(t, ok)
	assert.Equal(t, int32(1), docReopened.version)
	assert.False(t, docReopened.dirty)
	assert.Greater(t, docReopened.openID, doc1.openID)

	// Open document with dirty flag: stored atomically with dirty state.
	dirtyPath := filepath.Join(t.TempDir(), "dirty.yaml")
	dirtyURI := uriFromPath(dirtyPath)
	store.open(dirtyURI, dirtyPath, 3, true)
	docDirty, ok := store.get(dirtyPath)
	require.True(t, ok)
	assert.Equal(t, dirtyURI, docDirty.uri)
	assert.Equal(t, dirtyPath, docDirty.path)
	assert.Equal(t, int32(3), docDirty.version)
	assert.True(t, docDirty.dirty)
	assert.Greater(t, docDirty.openID, docReopened.openID)
}
