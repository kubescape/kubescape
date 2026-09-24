package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadNamespaceFilters(t *testing.T) {
	for _, tt := range []struct {
		name, document string
		want           NamespaceFilters
		invalid        bool
	}{
		{"arrays", `{"includeNamespaces":["prod","payments"],"excludeNamespaces":["test"]}`, NamespaceFilters{"prod,payments", "test"}, false},
		{"strings", `{"includeNamespaces":" prod, payments ","excludeNamespaces":" test "}`, NamespaceFilters{"prod,payments", "test"}, false},
		{"clear", `{"includeNamespaces":[],"excludeNamespaces":""}`, NamespaceFilters{}, false},
		{"missing include", `{"excludeNamespaces":[]}`, NamespaceFilters{}, true},
		{"missing exclude", `{"includeNamespaces":[]}`, NamespaceFilters{}, true},
		{"null document", `null`, NamespaceFilters{}, true},
		{"null list", `{"includeNamespaces":null,"excludeNamespaces":[]}`, NamespaceFilters{}, true},
		{"invalid type", `{"includeNamespaces":true,"excludeNamespaces":[]}`, NamespaceFilters{}, true},
		{"invalid element", `{"includeNamespaces":[42],"excludeNamespaces":[]}`, NamespaceFilters{}, true},
		{"invalid name", `{"includeNamespaces":["prod/*"],"excludeNamespaces":[]}`, NamespaceFilters{}, true},
		{"unknown field", `{"includeNamespaces":[],"excludeNamespaces":[],"typo":[]}`, NamespaceFilters{}, true},
		{"regex unsupported", `{"includeNamespaces":[],"excludeNamespaces":[],"includeNamespacesRegex":[".*"]}`, NamespaceFilters{}, true},
		{"truncated", `{"includeNamespaces":[]`, NamespaceFilters{}, true},
		{"multiple documents", `{"includeNamespaces":[],"excludeNamespaces":[]} {}`, NamespaceFilters{}, true},
		{"trailing garbage", `{"includeNamespaces":[],"excludeNamespaces":[]} invalid`, NamespaceFilters{}, true},
		{"too large", strings.Repeat(" ", (1<<20)+1), NamespaceFilters{}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "namespaceFilters.json")
			require.NoError(t, os.WriteFile(path, []byte(tt.document), 0o600))
			got, err := readNamespaceFilters(path)
			if tt.invalid {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.want, got)
			}
		})
	}
}

func preserveNamespaceFilters(t *testing.T) {
	t.Helper()
	previous := namespaceFiltersSource.Load()
	t.Cleanup(func() { namespaceFiltersSource.Store(previous) })
}

func TestNamespaceFiltersReload(t *testing.T) {
	preserveNamespaceFilters(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "namespaceFilters.json")
	require.Error(t, ConfigureNamespaceFilters(path))
	require.NoError(t, os.WriteFile(path, []byte(`{"includeNamespaces":["prod"],"excludeNamespaces":[]}`), 0o600))
	require.NoError(t, ConfigureNamespaceFilters(path))
	assertFilters := func(want NamespaceFilters) {
		t.Helper()
		got, enabled := GetNamespaceFilters()
		require.True(t, enabled)
		require.Equal(t, want, got)
	}
	assertFilters(NamespaceFilters{Include: "prod"})
	// A bad update must not clear either part of the previous snapshot.
	require.NoError(t, os.WriteFile(path, []byte(`{"includeNamespaces":[],"excludeNamespaces":false}`), 0o600))
	assertFilters(NamespaceFilters{Include: "prod"})
	require.NoError(t, os.Remove(path))
	assertFilters(NamespaceFilters{Include: "prod"})
	// Recover after deletion, and switch from include to exclude atomically.
	require.NoError(t, os.WriteFile(path, []byte(`{"includeNamespaces":[],"excludeNamespaces":["test"]}`), 0o600))
	assertFilters(NamespaceFilters{Exclude: "test"})
	require.NoError(t, os.WriteFile(path, []byte(`{"includeNamespaces":[],"excludeNamespaces":[]}`), 0o600))
	assertFilters(NamespaceFilters{})
	require.NoError(t, ConfigureNamespaceFilters(""))
	_, enabled := GetNamespaceFilters()
	require.False(t, enabled)
}

func TestNamespaceFiltersProjectedVolumeAndConcurrentReaders(t *testing.T) {
	preserveNamespaceFilters(t)
	dir := t.TempDir()
	// Model kubelet's stable file symlink through an atomically replaced ..data.
	for _, name := range []string{"prod", "test"} {
		generation := filepath.Join(dir, name)
		require.NoError(t, os.Mkdir(generation, 0o700))
		document := fmt.Sprintf(`{"includeNamespaces":[%q],"excludeNamespaces":[%q]}`, name, name)
		require.NoError(t, os.WriteFile(filepath.Join(generation, "namespaceFilters.json"), []byte(document), 0o600))
	}
	require.NoError(t, os.Symlink("prod", filepath.Join(dir, "..data")))
	require.NoError(t, os.Symlink("..data/namespaceFilters.json", filepath.Join(dir, "namespaceFilters.json")))
	require.NoError(t, ConfigureNamespaceFilters(filepath.Join(dir, "namespaceFilters.json")))
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 30 {
				got, enabled := GetNamespaceFilters()
				if !enabled || got.Include != got.Exclude || (got.Include != "prod" && got.Include != "test") {
					t.Errorf("inconsistent snapshot: %+v (enabled=%v)", got, enabled)
				}
			}
		})
	}
	require.NoError(t, os.Symlink("test", filepath.Join(dir, "..data-new")))
	require.NoError(t, os.Rename(filepath.Join(dir, "..data-new"), filepath.Join(dir, "..data")))
	wg.Wait()
	got, enabled := GetNamespaceFilters()
	require.True(t, enabled)
	require.Equal(t, NamespaceFilters{"test", "test"}, got)
}
