package resourcehandler

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKustomizeWorkloadSource(t *testing.T) {
	root := t.TempDir()
	directory := reporthandling.Source{
		Path:                   root,
		RelativePath:           "overlay",
		FileType:               reporthandling.SourceTypeKustomizeDirectory,
		KustomizeDirectoryName: filepath.Join(root, "overlay"),
		LastCommit:             reporthandling.LastCommit{Hash: "directory-commit"},
	}

	lastCommitOf := func(file string) reporthandling.LastCommit {
		return reporthandling.LastCommit{Hash: "commit-of-" + filepath.ToSlash(file)}
	}

	t.Run("a file inside the scan root is the source, with its own commit", func(t *testing.T) {
		got := kustomizeWorkloadSource(directory, filepath.Join(root, "base", "deployment.yaml"), root, lastCommitOf)

		assert.Equal(t, filepath.Join("base", "deployment.yaml"), got.RelativePath)
		assert.Equal(t, "commit-of-base/deployment.yaml", got.LastCommit.Hash)
		assert.Equal(t, root, got.Path, "still relative to the same root")
		assert.Equal(t, reporthandling.SourceTypeKustomizeDirectory, got.FileType)
		assert.Equal(t, directory.KustomizeDirectoryName, got.KustomizeDirectoryName, "the directory is still recorded")
	})

	t.Run("the directory's own source is not changed", func(t *testing.T) {
		kustomizeWorkloadSource(directory, filepath.Join(root, "base", "deployment.yaml"), root, lastCommitOf)
		assert.Equal(t, "overlay", directory.RelativePath)
		assert.Equal(t, "directory-commit", directory.LastCommit.Hash)
	})

	t.Run("no known file keeps the directory", func(t *testing.T) {
		assert.Equal(t, directory, kustomizeWorkloadSource(directory, "", root, lastCommitOf))
	})

	t.Run("a file outside the scan root keeps the directory", func(t *testing.T) {
		outside := filepath.Join(filepath.Dir(root), "elsewhere", "deployment.yaml")
		assert.Equal(t, directory, kustomizeWorkloadSource(directory, outside, root, lastCommitOf),
			"a path relative to the root must not escape it")
	})

	t.Run("an unknown root keeps the directory", func(t *testing.T) {
		assert.Equal(t, directory, kustomizeWorkloadSource(directory, filepath.Join(root, "base", "deployment.yaml"), "", lastCommitOf))
	})

	t.Run("a symlink inside the root that leads outside keeps the directory", func(t *testing.T) {
		// Kustomize reads through the link, so the file exists and its path is
		// lexically inside the root. It is still not a file of this scan.
		outside := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(outside, "deployment.yaml"), []byte("kind: Deployment\n"), 0o600))
		if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
			t.Skipf("cannot create a symlink here: %v", err)
		}

		got := kustomizeWorkloadSource(directory, filepath.Join(root, "linked", "deployment.yaml"), root, lastCommitOf)

		assert.Equal(t, directory, got, "the resource is attributed to the directory, not to a file outside the scan")
	})

	t.Run("a symlink inside the root that leads to a file inside it is reported as it appears", func(t *testing.T) {
		require.NoError(t, os.MkdirAll(filepath.Join(root, "shared"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(root, "shared", "deployment.yaml"), []byte("kind: Deployment\n"), 0o600))
		if err := os.Symlink(filepath.Join(root, "shared"), filepath.Join(root, "alias")); err != nil {
			t.Skipf("cannot create a symlink here: %v", err)
		}

		got := kustomizeWorkloadSource(directory, filepath.Join(root, "alias", "deployment.yaml"), root, lastCommitOf)

		assert.Equal(t, filepath.Join("alias", "deployment.yaml"), got.RelativePath)
	})
}
