package scancache

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlushResetsDirty(t *testing.T) {
	dir := t.TempDir()
	s, err := Load(dir, "v1")
	require.NoError(t, err)

	s.Put("ctrl", "res", "hash", resourcesresults.ResourceAssociatedControl{})
	require.NoError(t, s.Flush())

	written, err := os.ReadFile(filepath.Join(dir, "incremental-scan-cache.json"))
	require.NoError(t, err)
	assert.Contains(t, string(written), `"ctrl|res"`)

	info1, err := os.Stat(filepath.Join(dir, "incremental-scan-cache.json"))
	require.NoError(t, err)

	// Second Flush without any Put should be a no-op (dirty was reset)
	require.NoError(t, s.Flush())

	info2, err := os.Stat(filepath.Join(dir, "incremental-scan-cache.json"))
	require.NoError(t, err)
	assert.Equal(t, info1.ModTime(), info2.ModTime(), "Flush should not rewrite the file when dirty is false")
}

func TestFlushSkipsCleanStore(t *testing.T) {
	dir := t.TempDir()
	s, err := Load(dir, "v1")
	require.NoError(t, err)

	// Flush on a clean store should be a no-op and not create the file
	require.NoError(t, s.Flush())
	_, err = os.Stat(filepath.Join(dir, "incremental-scan-cache.json"))
	assert.True(t, os.IsNotExist(err))
}

func TestPutDirtyFlag(t *testing.T) {
	dir := t.TempDir()
	s, err := Load(dir, "v1")
	require.NoError(t, err)

	s.Put("ctrl", "res", "hash", resourcesresults.ResourceAssociatedControl{})
	assert.True(t, s.dirty)

	require.NoError(t, s.Flush())
	assert.False(t, s.dirty)
}

func TestLoadCorruptCache(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "incremental-scan-cache.json"), []byte("not json"), 0o600)
	require.NoError(t, err)

	s, err := Load(dir, "v1")
	require.NoError(t, err)
	assert.Empty(t, s.data)
}

func TestLoadVersionMismatch(t *testing.T) {
	dir := t.TempDir()
	s := &Store{path: filepath.Join(dir, "incremental-scan-cache.json"), version: "v1", data: map[string]Entry{}}
	s.Put("ctrl", "res", "hash", resourcesresults.ResourceAssociatedControl{})
	require.NoError(t, s.Flush())

	loaded, err := Load(dir, "v2")
	require.NoError(t, err)
	assert.Empty(t, loaded.data)
}

func TestGetMissReturnsFalse(t *testing.T) {
	dir := t.TempDir()
	s, err := Load(dir, "v1")
	require.NoError(t, err)

	_, ok := s.Get("ctrl", "res", "hash")
	assert.False(t, ok)
}

func TestGetHitReturnsVerdict(t *testing.T) {
	dir := t.TempDir()
	s, err := Load(dir, "v1")
	require.NoError(t, err)

	verdict := resourcesresults.ResourceAssociatedControl{ControlID: "C-0001"}
	s.Put("ctrl", "res", "hash", verdict)
	require.NoError(t, s.Flush())

	loaded, err := Load(dir, "v1")
	require.NoError(t, err)

	got, ok := loaded.Get("ctrl", "res", "hash")
	assert.True(t, ok)
	assert.Equal(t, "C-0001", got.ControlID)
}

func TestGetHashMismatchReturnsFalse(t *testing.T) {
	dir := t.TempDir()
	s, err := Load(dir, "v1")
	require.NoError(t, err)

	s.Put("ctrl", "res", "hash1", resourcesresults.ResourceAssociatedControl{})
	require.NoError(t, s.Flush())

	_, ok := s.Get("ctrl", "res", "hash2")
	assert.False(t, ok)
}

func TestDelete(t *testing.T) {
	dir := t.TempDir()
	s := &Store{path: filepath.Join(dir, "incremental-scan-cache.json"), version: "v1", data: map[string]Entry{}}
	s.Put("ctrl", "res", "hash", resourcesresults.ResourceAssociatedControl{})
	require.NoError(t, s.Flush())

	require.NoError(t, Delete(dir))
	_, err := os.Stat(filepath.Join(dir, "incremental-scan-cache.json"))
	assert.True(t, os.IsNotExist(err))
}

func TestDeleteMissingFile(t *testing.T) {
	dir := t.TempDir()
	assert.NoError(t, Delete(dir))
}

func TestResourceHash(t *testing.T) {
	obj := map[string]any{
		"metadata": map[string]any{
			"name":            "test",
			"resourceVersion": "123",
			"managedFields":   []any{},
		},
		"status": map[string]any{"phase": "Running"},
	}

	h1 := ResourceHash(obj)
	h2 := ResourceHash(obj)
	assert.Equal(t, h1, h2, "same input should produce same hash")

	// Changing a non-stripped field changes the hash
	obj["metadata"].(map[string]any)["name"] = "changed"
	h3 := ResourceHash(obj)
	assert.NotEqual(t, h1, h3)
}

func TestVersionKey(t *testing.T) {
	k1 := VersionKey([]byte("a"), []byte("b"))
	k2 := VersionKey([]byte("a"), []byte("b"))
	k3 := VersionKey([]byte("a"), []byte("c"))
	assert.Equal(t, k1, k2)
	assert.NotEqual(t, k1, k3)
}
