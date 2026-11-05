package cautils

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	giturl "github.com/kubescape/go-git-url"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsGitRepoPublic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/public" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	tests := []struct {
		url  string
		want bool
	}{
		{
			url:  server.URL + "/public",
			want: true,
		},
		{
			url:  server.URL + "/private",
			want: false,
		},
		{
			url:  "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			assert.Equal(t, tt.want, isGitRepoPublic(tt.url))
		})
	}
}

func TestGetProviderError(t *testing.T) {
	tests := []struct {
		url string
		err error
	}{
		{
			url: "https://github.com/kubescape/kubescape/",
			err: fmt.Errorf("%w", errors.New("GITHUB_TOKEN is not present")),
		},
		{
			url: "https://gitlab.com/kubescape/kubescape/",
			err: fmt.Errorf("%w", errors.New("GITLAB_TOKEN is not present")),
		},
		{
			url: "https://dev.azure.com/kubescape/kubescape/",
			err: fmt.Errorf("%w", errors.New("AZURE_TOKEN is not present")),
		},
		{
			url: "https://bitbucket.org/kubescape/kubescape/",
			err: fmt.Errorf("%w", errors.New("BITBUCKET_TOKEN is not present")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			gitURL, _ := giturl.NewGitAPI(tt.url)
			assert.Equal(t, tt.err, getProviderError(gitURL))
		})
	}
}

func TestCloneRepo(t *testing.T) {
	resetRepoWorkspaceState(t)
	useFakeClone(t, func(path string, _ bool, options *git.CloneOptions) (*git.Repository, error) {
		return initializeCloneWorkspace(path, options)
	})
	gitURL := authenticatedGitURL(t, "https://github.com/kubescape/kubescape/")

	tempDir, err := cloneRepo(gitURL)

	require.NoError(t, err)
	assert.DirExists(t, tempDir)
	require.NoError(t, ReleaseClonedRepo("https://github.com/kubescape/kubescape/"))
}
func TestGetClonedPath(t *testing.T) {
	testCases := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "Valid Git URL",
			path:     "https://github.com/kubescape/kubescape.git",
			expected: "/path/to/cloned/repo", // replace with the expected path
		},
		{
			name:     "Invalid Git URL",
			path:     "invalid",
			expected: "",
		},
	}
	clonedPath := t.TempDir()
	tmpDirPaths = make(map[string]string)
	tmpDirPaths[hashRepoURL("https://github.com/kubescape/kubescape.git")] = clonedPath
	testCases[0].expected = clonedPath

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := GetClonedPath(tc.path)
			if result != tc.expected {
				t.Errorf("Expected %q, got %q", tc.expected, result)
			}
		})
	}
}
func TestGetDirPath(t *testing.T) {
	testCases := []struct {
		name     string
		repoURL  string
		expected string
	}{
		{
			name:     "Existing Repo URL",
			repoURL:  "https://github.com/user/repo.git",
			expected: "/path/to/cloned/repo", // replace with the expected path
		},
		{
			name:     "Non-Existing Repo URL",
			repoURL:  "https://github.com/user/nonexistentrepo.git",
			expected: "",
		},
	}

	// Initialize tmpDirPaths
	clonedPath := t.TempDir()
	tmpDirPaths = make(map[string]string)
	tmpDirPaths[hashRepoURL("https://github.com/user/repo.git")] = clonedPath
	testCases[0].expected = clonedPath

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := getDirPath(tc.repoURL)
			if result != tc.expected {
				t.Errorf("Expected %q, got %q", tc.expected, result)
			}
		})
	}
}

// TestHashRepoURL verifies that hashRepoURL returns a valid 64-character hex-encoded
// SHA-256 digest that is deterministic and unique per URL.
func TestHashRepoURL(t *testing.T) {
	url := "https://github.com/kubescape/kubescape.git"
	hash := hashRepoURL(url)

	assert.Len(t, hash, 64)
	decoded, err := hex.DecodeString(hash)
	require.NoError(t, err, "hash must be valid hexadecimal")
	assert.Len(t, decoded, 32, "decoded hash must be 32 bytes")

	// Ensure determinism
	assert.Equal(t, hash, hashRepoURL(url))

	// Ensure different URLs produce different hashes
	otherHash := hashRepoURL("https://github.com/kubescape/other.git")
	assert.NotEqual(t, hash, otherHash)
}

func TestCloneRepoShallowDepthOptions(t *testing.T) {
	tests := []struct {
		name          string
		depthOpt      []int
		url           string
		wantDepth     int
		wantSingle    bool
		wantRefBranch string
	}{
		{
			name:          "default depth is 1 with single branch",
			depthOpt:      nil,
			url:           "https://github.com/kubescape/kubescape/",
			wantDepth:     DefaultGitCloneDepth,
			wantSingle:    true,
			wantRefBranch: "",
		},
		{
			name:          "default depth with explicit branch",
			depthOpt:      nil,
			url:           "https://github.com/kubescape/kubescape/tree/feature-branch",
			wantDepth:     DefaultGitCloneDepth,
			wantSingle:    true,
			wantRefBranch: "refs/heads/feature-branch",
		},
		{
			name:          "explicit shallow depth",
			depthOpt:      []int{5},
			url:           "https://github.com/kubescape/kubescape/",
			wantDepth:     5,
			wantSingle:    true,
			wantRefBranch: "",
		},
		{
			name:          "full history opt out with depth 0",
			depthOpt:      []int{0},
			url:           "https://github.com/kubescape/kubescape/",
			wantDepth:     0,
			wantSingle:    true,
			wantRefBranch: "",
		},
		{
			name:          "negative depth defaults to DefaultGitCloneDepth",
			depthOpt:      []int{-1},
			url:           "https://github.com/kubescape/kubescape/",
			wantDepth:     DefaultGitCloneDepth,
			wantSingle:    true,
			wantRefBranch: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetRepoWorkspaceState(t)
			var capturedOpts *git.CloneOptions
			useFakeClone(t, func(path string, _ bool, options *git.CloneOptions) (*git.Repository, error) {
				capturedOpts = options
				return initializeCloneWorkspace(path, options)
			})

			gitURL := authenticatedGitURL(t, tt.url)
			tempDir, err := cloneRepo(gitURL, tt.depthOpt...)
			require.NoError(t, err)
			assert.DirExists(t, tempDir)

			require.NotNil(t, capturedOpts)
			assert.Equal(t, tt.wantDepth, capturedOpts.Depth)
			assert.Equal(t, tt.wantSingle, capturedOpts.SingleBranch)
			if tt.wantRefBranch != "" {
				assert.Equal(t, tt.wantRefBranch, string(capturedOpts.ReferenceName))
			} else {
				assert.Empty(t, capturedOpts.ReferenceName)
			}
			require.NoError(t, ReleaseClonedRepo(tt.url))
		})
	}
}

func TestCloneRepoCommitSHAFallback(t *testing.T) {
	// Discover the commit SHA generated by initializeCloneWorkspace
	tempPath := t.TempDir()
	initRepo, err := initializeCloneWorkspace(tempPath, &git.CloneOptions{URL: "https://github.com/kubescape/kubescape"})
	require.NoError(t, err)
	head, err := initRepo.Head()
	require.NoError(t, err)
	commitSHA := head.Hash().String()

	commitURLs := []string{
		"https://github.com/kubescape/kubescape/commit/" + commitSHA,
		"https://github.com/kubescape/kubescape/tree/" + commitSHA,
	}

	for _, u := range commitURLs {
		t.Run(u, func(t *testing.T) {
			resetRepoWorkspaceState(t)
			var capturedOpts *git.CloneOptions
			useFakeClone(t, func(path string, _ bool, options *git.CloneOptions) (*git.Repository, error) {
				capturedOpts = options
				repo, err := initializeCloneWorkspace(path, options)
				if err != nil {
					return nil, err
				}
				// Add a default-branch tip after the target commit so initial HEAD differs from commitSHA.
				worktree, err := repo.Worktree()
				if err != nil {
					return nil, err
				}
				if err := os.WriteFile(filepath.Join(path, "tip.yaml"), []byte("kind: Secret\n"), 0o600); err != nil {
					return nil, err
				}
				if _, err := worktree.Add("tip.yaml"); err != nil {
					return nil, err
				}
				signature := &object.Signature{Name: "test", Email: "test@example.com", When: time.Unix(2, 0)}
				if _, err := worktree.Commit("default branch tip", &git.CommitOptions{Author: signature, Committer: signature}); err != nil {
					return nil, err
				}
				return repo, nil
			})

			gitURL := authenticatedGitURL(t, u)
			tempDir, err := cloneRepo(gitURL, 1) // requested depth 1 should fall back to 0 for commit SHA
			require.NoError(t, err)
			assert.DirExists(t, tempDir)

			require.NotNil(t, capturedOpts)
			assert.Equal(t, 0, capturedOpts.Depth, "commit SHA must fall back to full clone Depth=0")
			assert.False(t, capturedOpts.SingleBranch, "commit SHA must not enforce single branch")
			assert.Empty(t, capturedOpts.ReferenceName, "commit SHA must not set branch reference name")

			repo, err := git.PlainOpen(tempDir)
			require.NoError(t, err)
			openedHead, err := repo.Head()
			require.NoError(t, err)
			assert.Equal(t, commitSHA, openedHead.Hash().String(), "worktree HEAD must be checked out at the requested commit")

			require.NoError(t, ReleaseClonedRepo(u))
		})
	}
}

func TestRepoWorkspaceKeyIsolatesCommitSHAs(t *testing.T) {
	shaA := authenticatedGitURL(t, "https://github.com/kubescape/kubescape/commit/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	shaB := authenticatedGitURL(t, "https://github.com/kubescape/kubescape/commit/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	master := authenticatedGitURL(t, "https://github.com/kubescape/kubescape/tree/master")
	root := authenticatedGitURL(t, "https://github.com/kubescape/kubescape")

	keyA := repoWorkspaceKey(shaA, 1)
	keyB := repoWorkspaceKey(shaB, 1)
	keyMaster := repoWorkspaceKey(master, 1)
	keyRoot := repoWorkspaceKey(root, 1)
	keyRootFull := repoWorkspaceKey(root, 0)

	assert.NotEqual(t, keyA, keyB, "different commit SHAs must have distinct workspace keys")
	assert.NotEqual(t, keyA, keyMaster, "commit SHA must not share workspace key with master branch")
	assert.NotEqual(t, keyA, keyRoot, "commit SHA must not share workspace key with root URL")
	assert.NotEqual(t, keyRoot, keyRootFull, "different clone depths must produce distinct workspace keys")
}

func TestCloneRepo_DifferentDepthsDoNotReuseWorkspace(t *testing.T) {
	resetRepoWorkspaceState(t)
	var cloneCalls int
	useFakeClone(t, func(path string, _ bool, options *git.CloneOptions) (*git.Repository, error) {
		cloneCalls++
		return initializeCloneWorkspace(path, options)
	})

	gitURL := authenticatedGitURL(t, "https://github.com/kubescape/kubescape/")

	// Clone 1: shallow depth 1
	path1, err := cloneRepo(gitURL, 1)
	require.NoError(t, err)
	assert.Equal(t, 1, cloneCalls)

	// Clone 2: full history depth 0 - must execute a second clone, not reuse depth 1
	path2, err := cloneRepo(gitURL, 0)
	require.NoError(t, err)
	assert.Equal(t, 2, cloneCalls, "different clone depths must not reuse the same workspace")
	assert.NotEqual(t, path1, path2, "workspaces for different depths must have distinct directories")

	require.NoError(t, ReleaseClonedRepo("https://github.com/kubescape/kubescape/", 1))
	require.NoError(t, ReleaseClonedRepo("https://github.com/kubescape/kubescape/", 0))
}

func TestCloneGitRepoPassesDepth(t *testing.T) {
	resetRepoWorkspaceState(t)
	var capturedOpts *git.CloneOptions
	useFakeClone(t, func(path string, _ bool, options *git.CloneOptions) (*git.Repository, error) {
		capturedOpts = options
		return initializeCloneWorkspace(path, options)
	})

	t.Setenv("GITHUB_TOKEN", "test-token")
	rawURL := "https://github.com/kubescape/kubescape"
	clonedDir, err := CloneGitRepo(&rawURL, 3)
	require.NoError(t, err)
	assert.DirExists(t, clonedDir)

	require.NotNil(t, capturedOpts)
	assert.Equal(t, 3, capturedOpts.Depth)
	assert.True(t, capturedOpts.SingleBranch)
	require.NoError(t, ReleaseClonedRepo("https://github.com/kubescape/kubescape"))
}
