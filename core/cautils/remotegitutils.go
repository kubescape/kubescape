package cautils

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	nethttp "net/http"
	"os"
	"sync"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	giturl "github.com/kubescape/go-git-url"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"golang.org/x/sync/singleflight"
)

const gitVisibilityCheckTimeout = 10 * time.Second

var (
	tmpDirPaths      = make(map[string]string)
	tmpDirRefs       = make(map[string]int)
	tmpDirPathsMu    sync.Mutex
	cloneGroup       singleflight.Group
	plainClone       = git.PlainClone
	gitTransportOnce sync.Once
)

// hashRepoURL returns a hex-encoded SHA-256 digest of the given repository URL.
func hashRepoURL(repoURL string) string {
	h := sha256.New()
	h.Write([]byte(repoURL))
	return hex.EncodeToString(h.Sum(nil))
}

func repoWorkspaceKey(gitURL giturl.IGitAPI) string {
	cloneURL := gitURL.GetHttpCloneURL()
	if gitURL.GetBranchName() == "" {
		return hashRepoURL(cloneURL)
	}
	return hashRepoURL(cloneURL + "\x00" + gitURL.GetBranchName())
}

func getDirPath(repoURL string) string {
	return getDirPathByKey(hashRepoURL(repoURL))
}

func getDirPathByKey(key string) string {
	tmpDirPathsMu.Lock()
	defer tmpDirPathsMu.Unlock()

	path := tmpDirPaths[key]
	if path == "" {
		return ""
	}
	if info, err := os.Stat(path); err != nil || !info.IsDir() {
		delete(tmpDirPaths, key)
		delete(tmpDirRefs, key)
		return ""
	}
	return path
}

func reserveWorkspace(key string) string {
	tmpDirPathsMu.Lock()
	defer tmpDirPathsMu.Unlock()
	path := tmpDirPaths[key]
	if path != "" {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			tmpDirRefs[key]++
			return path
		}
		delete(tmpDirPaths, key)
		delete(tmpDirRefs, key)
	}
	tmpDirRefs[key]++
	return ""
}

func cancelWorkspaceReservation(key string) {
	tmpDirPathsMu.Lock()
	defer tmpDirPathsMu.Unlock()
	if tmpDirRefs[key] <= 1 {
		delete(tmpDirRefs, key)
		return
	}
	tmpDirRefs[key]--
}

// createTempDir creates an unregistered workspace. A path is published only
// after the clone succeeds, so callers can never observe a partial repository.
func createTempDir() (string, error) {
	// create temp directory
	tmpDir, err := os.MkdirTemp("", "kubescape-git-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary directory: %w", err)
	}
	return tmpDir, nil
}

// To Check if the given repository is Public(No Authentication needed), send a HTTP GET request to the URL
// If response code is 200, the repository is Public.
func isGitRepoPublic(u string) bool {
	client := &nethttp.Client{Timeout: gitVisibilityCheckTimeout}
	resp, err := client.Get(u)
	if err != nil {
		return false
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// if the status code is 200, our get request is successful.
	// It only happens when the repository is public.
	return resp.StatusCode == nethttp.StatusOK
}

// Check if the GITHUB_TOKEN is present
func isGitTokenPresent(gitURL giturl.IGitAPI) bool {
	if token := gitURL.GetToken(); token == "" {
		return false
	}
	return true
}

// Get the error message according to the provider
func getProviderError(gitURL giturl.IGitAPI) error {
	switch gitURL.GetProvider() {
	case "github":
		return fmt.Errorf("%w", errors.New("GITHUB_TOKEN is not present"))
	case "gitlab":
		return fmt.Errorf("%w", errors.New("GITLAB_TOKEN is not present"))
	case "azure":
		return fmt.Errorf("%w", errors.New("AZURE_TOKEN is not present"))
	case "bitbucket":
		return fmt.Errorf("%w", errors.New("BITBUCKET_TOKEN is not present"))
	}
	return fmt.Errorf("%w", errors.New("unable to find the host name"))
}

// cloneRepo clones a repository to a local temporary directory and returns the directory
func cloneRepo(gitURL giturl.IGitAPI) (string, error) {
	// This is a process-wide go-git setting. Configure it once before any
	// clone starts so different repositories can be cloned concurrently
	// without racing on transport.UnsupportedCapabilities.
	gitTransportOnce.Do(func() {
		transport.UnsupportedCapabilities = []capability.Capability{
			capability.ThinPack,
		}
	})

	cloneURL := gitURL.GetHttpCloneURL()
	key := repoWorkspaceKey(gitURL)
	if path := reserveWorkspace(key); path != "" {
		return path, nil
	}

	value, err, _ := cloneGroup.Do(key, func() (interface{}, error) {
		if path := getDirPathByKey(key); path != "" {
			return path, nil
		}

		tmpDir, err := createTempDir()
		if err != nil {
			return "", err
		}
		keepWorkspace := false
		defer func() {
			if !keepWorkspace {
				_ = os.RemoveAll(tmpDir)
			}
		}()

		isGitTokenPresent := isGitTokenPresent(gitURL)

		// Declare the authentication variable required for cloneOptions
		var auth transport.AuthMethod

		if isGitTokenPresent {
			auth = &http.BasicAuth{
				Username: "x-token-auth",
				Password: gitURL.GetToken(),
			}
		} else {
			// If the repository is public, no authentication is needed
			if isGitRepoPublic(cloneURL) {
				auth = nil
			} else {
				return "", getProviderError(gitURL)
			}
		}

		// Clone option
		cloneOpts := git.CloneOptions{URL: cloneURL, Auth: auth}
		if gitURL.GetBranchName() != "" {
			cloneOpts.ReferenceName = plumbing.NewBranchReferenceName(gitURL.GetBranchName())
			cloneOpts.SingleBranch = true
		}

		// Actual clone
		if _, err = plainClone(tmpDir, false, &cloneOpts); err != nil {
			return "", fmt.Errorf("failed to clone %s: %w", gitURL.GetRepoName(), err)
		}

		tmpDirPathsMu.Lock()
		tmpDirPaths[key] = tmpDir
		tmpDirPathsMu.Unlock()
		keepWorkspace = true
		return tmpDir, nil
	})
	if err != nil {
		cancelWorkspaceReservation(key)
		return "", err
	}

	return value.(string), nil
}

// ReleaseClonedRepo releases one scan's ownership of a cloned repository. The
// workspace is deleted only after the last scan using it has finished.
func ReleaseClonedRepo(path string) error {
	gitURL, err := giturl.NewGitAPI(path)
	if err != nil {
		return err
	}
	key := repoWorkspaceKey(gitURL)

	tmpDirPathsMu.Lock()
	workspace := tmpDirPaths[key]
	if workspace == "" {
		tmpDirPathsMu.Unlock()
		return nil
	}
	if tmpDirRefs[key] > 1 {
		tmpDirRefs[key]--
		tmpDirPathsMu.Unlock()
		return nil
	}
	delete(tmpDirPaths, key)
	delete(tmpDirRefs, key)
	tmpDirPathsMu.Unlock()

	if err := os.RemoveAll(workspace); err != nil {
		return fmt.Errorf("failed to remove cloned repository %s: %w", workspace, err)
	}
	return nil
}

// CloneGitRepo clone git repository
func CloneGitRepo(path *string) (string, error) {
	var clonedDir string

	gitURL, err := giturl.NewGitAPI(*path)
	if err != nil {
		return "", err
	}

	// Clone git repository if needed
	logger.L().Start("cloning", helpers.String("repository url", gitURL.GetURL().String()))

	clonedDir, err = cloneRepo(gitURL)
	if err != nil {
		logger.L().StopError("failed to clone git repo", helpers.String("url", gitURL.GetURL().String()), helpers.Error(err))
		return "", fmt.Errorf("failed to clone git repo '%s',  %w", gitURL.GetURL().String(), err)
	}
	*path = clonedDir

	logger.L().StopSuccess("Done accessing remote repo")

	return clonedDir, nil
}

func GetClonedPath(path string) string {

	gitURL, err := giturl.NewGitAPI(path)
	if err != nil {
		return ""
	}

	return getDirPathByKey(repoWorkspaceKey(gitURL))
}
