package cautils

import (
	"context"
	"errors"
	"fmt"
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

func TestCloneRepoClonesDifferentRepositoriesConcurrently(t *testing.T) {
	resetRepoWorkspaceState(t)
	const repositories = 4
	cloneStarted := make(chan struct{}, repositories)
	releaseClones := make(chan struct{})
	useFakeClone(t, func(_ string, _ bool, _ *git.CloneOptions) (*git.Repository, error) {
		cloneStarted <- struct{}{}
		<-releaseClones
		return &git.Repository{}, nil
	})

	errs := make(chan error, repositories)
	urls := make([]string, repositories)
	for i := range repositories {
		urls[i] = fmt.Sprintf("https://github.com/example/project-%d", i)
		gitURL := authenticatedGitURL(t, urls[i])
		go func() {
			_, err := cloneRepo(gitURL)
			errs <- err
		}()
	}

	for range repositories {
		<-cloneStarted
	}
	close(releaseClones)
	for range repositories {
		require.NoError(t, <-errs)
	}
	for _, url := range urls {
		require.NoError(t, ReleaseClonedRepo(url))
	}
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
	assert.Equal(t, int32(0), cloneCalls.Load())

	require.NoError(t, scanInfo.MaterializeRemoteInputs(context.Background()))
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

func TestScanningContextClonesTrailingRemoteInputAfterLocalInput(t *testing.T) {
	resetRepoWorkspaceState(t)
	t.Setenv("GITHUB_TOKEN", "test-token")
	var cloneCalls atomic.Int32
	useFakeClone(t, func(path string, _ bool, options *git.CloneOptions) (*git.Repository, error) {
		cloneCalls.Add(1)
		return initializeCloneWorkspace(path, options)
	})

	remoteInput := "https://github.com/example/remote"
	scanInfo := &ScanInfo{InputPatterns: []string{t.TempDir(), remoteInput}}
	require.Equal(t, ContextDir, scanInfo.GetScanningContext())
	assert.Equal(t, int32(0), cloneCalls.Load())

	require.NoError(t, scanInfo.MaterializeRemoteInputs(context.Background()))
	assert.Equal(t, int32(1), cloneCalls.Load())

	workspace := GetClonedPath(remoteInput)
	require.NotEmpty(t, workspace)
	assert.DirExists(t, workspace)

	scanInfo.Cleanup()
	assert.Empty(t, GetClonedPath(remoteInput))
	assert.NoDirExists(t, workspace)
}

func TestMaterializeRemoteInputsPropagatesError(t *testing.T) {
	resetRepoWorkspaceState(t)
	t.Setenv("GITHUB_TOKEN", "test-token")
	useFakeClone(t, func(path string, _ bool, options *git.CloneOptions) (*git.Repository, error) {
		return nil, errors.New("authentication failed: 401 Unauthorized")
	})

	remoteInput := "https://github.com/example/private-repo"
	scanInfo := &ScanInfo{InputPatterns: []string{remoteInput}}
	require.Equal(t, ContextGitRemote, scanInfo.GetScanningContext())

	err := scanInfo.MaterializeRemoteInputs(context.Background())
	require.Error(t, err)
	assert.ErrorContains(t, err, "failed to clone remote git repository")
	assert.ErrorContains(t, err, "401 Unauthorized")
	assert.Empty(t, GetClonedPath(remoteInput))
}

func TestScanInfoInitPropagatesCloneError(t *testing.T) {
	resetRepoWorkspaceState(t)
	t.Setenv("GITHUB_TOKEN", "test-token")
	useFakeClone(t, func(path string, _ bool, options *git.CloneOptions) (*git.Repository, error) {
		return nil, errors.New("repository not found")
	})

	remoteInput := "https://github.com/example/nonexistent-repo"
	scanInfo := &ScanInfo{InputPatterns: []string{remoteInput}}
	err := scanInfo.Init(context.Background(), nil)
	require.Error(t, err)
	assert.ErrorContains(t, err, "failed to clone remote git repository")
	assert.ErrorContains(t, err, "repository not found")
}

// TestMaterializeRemoteInputsPreCloneCancellation verifies that a cancelled
// context prevents any clone from starting. This is pre-clone cancellation
// only; an already-running git.PlainClone is not interrupted because
// CloneGitRepo does not accept a context today.
func TestMaterializeRemoteInputsPreCloneCancellation(t *testing.T) {
	resetRepoWorkspaceState(t)
	var cloneCalls atomic.Int32
	useFakeClone(t, func(path string, _ bool, options *git.CloneOptions) (*git.Repository, error) {
		cloneCalls.Add(1)
		return initializeCloneWorkspace(path, options)
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	scanInfo := &ScanInfo{InputPatterns: []string{"https://github.com/example/repo"}}
	err := scanInfo.MaterializeRemoteInputs(ctx)
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, int32(0), cloneCalls.Load())
}

// TestScanInfoCleanupSequentialIdempotency verifies that cleanup hooks are
// consumed on first call, so repeated sequential calls are safe. This matters
// because MaterializeRemoteInputs calls Cleanup() on failure to roll back
// partial clones, and the outer scan lifecycle calls it again via defer.
// Note: this is sequential idempotency, not concurrent safety.
func TestScanInfoCleanupSequentialIdempotency(t *testing.T) {
	var count int
	scanInfo := &ScanInfo{}
	scanInfo.AddCleanup(func() {
		count++
	})
	scanInfo.Cleanup()
	assert.Equal(t, 1, count)
	scanInfo.Cleanup()
	assert.Equal(t, 1, count)
}


