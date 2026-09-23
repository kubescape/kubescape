package cautils

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-git/go-git/v5"
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
