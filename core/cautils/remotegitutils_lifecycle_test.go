package cautils

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	giturl "github.com/kubescape/go-git-url"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/singleflight"
)

func resetRepoWorkspaceState(t *testing.T) {
	t.Helper()
	tmpDirPathsMu.Lock()
	paths := make([]string, 0, len(tmpDirPaths))
	for _, path := range tmpDirPaths {
		paths = append(paths, path)
	}
	tmpDirPaths = make(map[string]string)
	tmpDirRefs = make(map[string]int)
	tmpDirPathsMu.Unlock()
	cloneGroup = singleflight.Group{}
	for _, path := range paths {
		require.NoError(t, os.RemoveAll(path))
	}
}

func useFakeClone(t *testing.T, clone func(string, bool, *git.CloneOptions) (*git.Repository, error)) {
	t.Helper()
	original := plainClone
	plainClone = clone
	t.Cleanup(func() {
		plainClone = original
		resetRepoWorkspaceState(t)
	})
}

func authenticatedGitURL(t *testing.T, rawURL string) giturl.IGitAPI {
	t.Helper()
	parsed, err := giturl.NewGitAPI(rawURL)
	require.NoError(t, err)
	parsed.SetToken("test-token")
	return parsed
}

func initializeCloneWorkspace(path string, options *git.CloneOptions) (*git.Repository, error) {
	repository, err := git.PlainInit(path, false)
	if err != nil {
		return nil, err
	}
	worktree, err := repository.Worktree()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(path, "manifest.yaml"), []byte("kind: ConfigMap\n"), 0o600); err != nil {
		return nil, err
	}
	if _, err := worktree.Add("manifest.yaml"); err != nil {
		return nil, err
	}
	signature := &object.Signature{Name: "test", Email: "test@example.com", When: time.Unix(1, 0)}
	if _, err := worktree.Commit("initial commit", &git.CommitOptions{Author: signature, Committer: signature}); err != nil {
		return nil, err
	}
	if _, err := repository.CreateRemote(&config.RemoteConfig{Name: "origin", URLs: []string{options.URL}}); err != nil {
		return nil, err
	}
	return repository, nil
}

func TestCloneRepoDeduplicatesConcurrentClonesAndReferenceCountsUsers(t *testing.T) {
	resetRepoWorkspaceState(t)
	var cloneCalls atomic.Int32
	cloneStarted := make(chan struct{})
	releaseClone := make(chan struct{})
	var startOnce sync.Once
	useFakeClone(t, func(path string, _ bool, _ *git.CloneOptions) (*git.Repository, error) {
		cloneCalls.Add(1)
		startOnce.Do(func() { close(cloneStarted) })
		<-releaseClone
		return &git.Repository{}, nil
	})

	const users = 8
	results := make(chan string, users)
	errors := make(chan error, users)
	for i := 0; i < users; i++ {
		parsed := authenticatedGitURL(t, "https://github.com/example/project")
		go func(gitURL giturl.IGitAPI) {
			path, err := cloneRepo(gitURL)
			results <- path
			errors <- err
		}(parsed)
	}
	<-cloneStarted
	close(releaseClone)

	var workspace string
	for i := 0; i < users; i++ {
		require.NoError(t, <-errors)
		path := <-results
		if workspace == "" {
			workspace = path
		}
		assert.Equal(t, workspace, path)
	}
	assert.Equal(t, int32(1), cloneCalls.Load())

	for i := 0; i < users-1; i++ {
		require.NoError(t, ReleaseClonedRepo("https://github.com/example/project"))
		assert.DirExists(t, workspace)
	}
	require.NoError(t, ReleaseClonedRepo("https://github.com/example/project"))
	assert.NoDirExists(t, workspace)
	assert.Empty(t, GetClonedPath("https://github.com/example/project"))
}

func TestCloneRepoDoesNotPublishOrLeakFailedWorkspace(t *testing.T) {
	resetRepoWorkspaceState(t)
	var attemptedPath string
	useFakeClone(t, func(path string, _ bool, _ *git.CloneOptions) (*git.Repository, error) {
		attemptedPath = path
		return nil, errors.New("clone interrupted")
	})

	_, err := cloneRepo(authenticatedGitURL(t, "https://github.com/example/broken"))
	require.ErrorContains(t, err, "clone interrupted")
	assert.NotEmpty(t, attemptedPath)
	assert.NoDirExists(t, attemptedPath)
	assert.Empty(t, GetClonedPath("https://github.com/example/broken"))
}

func TestCloneRepoKeepsBranchesInSeparateWorkspaces(t *testing.T) {
	resetRepoWorkspaceState(t)
	var cloneCalls atomic.Int32
	useFakeClone(t, func(path string, _ bool, _ *git.CloneOptions) (*git.Repository, error) {
		cloneCalls.Add(1)
		return &git.Repository{}, nil
	})

	mainURL := "https://github.com/example/project/tree/main"
	featureURL := "https://github.com/example/project/tree/feature"
	mainPath, err := cloneRepo(authenticatedGitURL(t, mainURL))
	require.NoError(t, err)
	featurePath, err := cloneRepo(authenticatedGitURL(t, featureURL))
	require.NoError(t, err)

	assert.NotEqual(t, mainPath, featurePath)
	assert.Equal(t, int32(2), cloneCalls.Load())
	assert.Equal(t, mainPath, GetClonedPath(mainURL))
	assert.Equal(t, featurePath, GetClonedPath(featureURL))

	require.NoError(t, ReleaseClonedRepo(mainURL))
	assert.NoDirExists(t, mainPath)
	assert.DirExists(t, featurePath)
	require.NoError(t, ReleaseClonedRepo(featureURL))
	assert.NoDirExists(t, featurePath)
}

func TestGetClonedPathEvictsDeletedWorkspace(t *testing.T) {
	resetRepoWorkspaceState(t)
	workspace := t.TempDir()
	url := "https://github.com/example/stale.git"
	key := hashRepoURL(url)
	tmpDirPathsMu.Lock()
	tmpDirPaths[key] = workspace
	tmpDirRefs[key] = 1
	tmpDirPathsMu.Unlock()
	require.NoError(t, os.RemoveAll(workspace))

	assert.Empty(t, getDirPath(url))
	tmpDirPathsMu.Lock()
	defer tmpDirPathsMu.Unlock()
	assert.NotContains(t, tmpDirPaths, key)
	assert.NotContains(t, tmpDirRefs, key)
}

func TestScanningContextClonesAndCleansEveryRemoteInput(t *testing.T) {
	resetRepoWorkspaceState(t)
	t.Setenv("GITHUB_TOKEN", "test-token")
	var cloneCalls atomic.Int32
	useFakeClone(t, func(path string, _ bool, options *git.CloneOptions) (*git.Repository, error) {
		cloneCalls.Add(1)
		return initializeCloneWorkspace(path, options)
	})

	inputs := []string{
		"https://github.com/example/first",
		"https://github.com/example/second",
	}
	scanInfo := &ScanInfo{InputPatterns: inputs}
	require.Equal(t, ContextGitRemote, scanInfo.GetScanningContext())
	assert.Equal(t, int32(2), cloneCalls.Load())

	workspaces := make([]string, 0, len(inputs))
	for _, input := range inputs {
		workspace := GetClonedPath(input)
		require.NotEmpty(t, workspace)
		assert.DirExists(t, workspace)
		workspaces = append(workspaces, workspace)
	}

	scanInfo.Cleanup()
	for i, input := range inputs {
		assert.Empty(t, GetClonedPath(input))
		assert.NoDirExists(t, workspaces[i])
	}
}
