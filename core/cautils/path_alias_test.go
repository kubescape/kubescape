package cautils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsUnderAnyDirUsesPathAliases(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	require.NoError(t, os.MkdirAll(appDir, 0o750))

	source := filepath.Join(appDir, "deployment.yaml")

	assert.True(t, IsUnderAnyDir(source, []string{appDir}))
	assert.False(t, IsUnderAnyDir(filepath.Join(root, "app-docs", "policy.yaml"), []string{appDir}))
}

func TestIsUnderAnyDirMatchesLexicalPathBelowPhysicalDir(t *testing.T) {
	physicalRoot := t.TempDir()
	physicalApp := filepath.Join(physicalRoot, "app")
	require.NoError(t, os.MkdirAll(physicalApp, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(physicalApp, "deployment.yaml"), []byte("kind: Pod\n"), 0o600))

	linkedRoot := filepath.Join(t.TempDir(), "linked-root")
	if err := os.Symlink(physicalRoot, linkedRoot); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	lexicalSource := filepath.Join(linkedRoot, "app", "deployment.yaml")

	assert.True(t, IsUnderAnyDir(lexicalSource, []string{physicalApp}))
}

func TestIsUnderAnyDirMatchesPhysicalPathBelowLexicalDir(t *testing.T) {
	physicalRoot := t.TempDir()
	physicalApp := filepath.Join(physicalRoot, "app")
	require.NoError(t, os.MkdirAll(physicalApp, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(physicalApp, "deployment.yaml"), []byte("kind: Pod\n"), 0o600))

	linkedRoot := filepath.Join(t.TempDir(), "linked-root")
	if err := os.Symlink(physicalRoot, linkedRoot); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	lexicalDir := filepath.Join(linkedRoot, "app")
	physicalSource := filepath.Join(physicalApp, "deployment.yaml")

	assert.True(t, IsUnderAnyDir(physicalSource, []string{lexicalDir}))
}

func TestIsUnderAnyDirHandlesRootDirectory(t *testing.T) {
	root := string(filepath.Separator)
	source := filepath.Join(root, "tmp", "deployment.yaml")

	assert.True(t, IsUnderAnyDir(source, []string{root}))
}

func TestIsUnderAnyDirRejectsPrefixSiblings(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	appDocsFile := filepath.Join(root, "app-docs", "policy.yaml")

	require.NoError(t, os.MkdirAll(appDir, 0o750))
	require.NoError(t, os.MkdirAll(filepath.Dir(appDocsFile), 0o750))

	assert.False(t, IsUnderAnyDir(appDocsFile, []string{appDir}))
}

func TestIsAnyPathAliasUnderAnyDirUsesNormalizedDirs(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	source := filepath.Join(appDir, "deployment.yaml")
	require.NoError(t, os.MkdirAll(appDir, 0o750))

	assert.True(t, IsAnyPathAliasUnderAnyDir(source, pathAliasesForPaths([]string{appDir})))
}
