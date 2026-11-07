package cautils

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	nethttp "net/http"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	giturl "github.com/kubescape/go-git-url"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"golang.org/x/sync/singleflight"
)

const (
	gitVisibilityCheckTimeout = 10 * time.Second

	// DefaultGitCloneDepth is the default shallow clone depth for remote Git repository scans.
	DefaultGitCloneDepth = 1
)

var (
	tmpDirPaths      = make(map[string]string)
	tmpDirRefs       = make(map[string]int)
	repoActiveKeys   = make(map[string]string)
	tmpDirPathsMu    sync.Mutex
	cloneGroup       singleflight.Group
	plainClone       = git.PlainClone
	gitTransportOnce sync.Once
	hexShaRegex      = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
)

// isCommitSHA checks whether a string is a 40-character hexadecimal Git commit SHA.
func isCommitSHA(s string) bool {
	return hexShaRegex.MatchString(s)
}

// extractCommitSHA extracts the target commit SHA from a giturl API object, if present.
func extractCommitSHA(gitURL giturl.IGitAPI) string {
	if gitURL.GetBranchName() == "commit" && isCommitSHA(gitURL.GetPath()) {
		return gitURL.GetPath()
	}
	if isCommitSHA(gitURL.GetBranchName()) {
		return gitURL.GetBranchName()
	}
	return ""
}

// hashRepoURL returns a hex-encoded SHA-256 digest of the given repository URL.
func hashRepoURL(repoURL string) string {
	h := sha256.New()
	h.Write([]byte(repoURL))
	return hex.EncodeToString(h.Sum(nil))
}

// repoBaseKey returns a hash key identifying the repository URL and branch or commit SHA.
func repoBaseKey(gitURL giturl.IGitAPI) string {
	cloneURL := gitURL.GetHttpCloneURL()
	if commitSHA := extractCommitSHA(gitURL); commitSHA != "" {
		return hashRepoURL(cloneURL + "\x00" + commitSHA)
	}
	if gitURL.GetBranchName() == "" {
		return hashRepoURL(cloneURL)
	}
	return hashRepoURL(cloneURL + "\x00" + gitURL.GetBranchName())
}

// repoWorkspaceKey returns a hash key identifying the repository, branch/commit, and effective clone depth.
func repoWorkspaceKey(gitURL giturl.IGitAPI, depthOpt ...int) string {
	depth := DefaultGitCloneDepth
	if len(depthOpt) > 0 {
		depth = depthOpt[0]
	}
	if extractCommitSHA(gitURL) != "" {
		depth = 0
	} else if depth < 0 {
		depth = DefaultGitCloneDepth
	}
	baseKey := repoBaseKey(gitURL)
	return hashRepoURL(fmt.Sprintf("%s\x00depth:%d", baseKey, depth))
}

// getDirPath returns the path of a cached workspace by repository URL, or empty if not present.
func getDirPath(repoURL string) string {
	return getDirPathByKey(hashRepoURL(repoURL))
}

// getDirPathByKey returns the path of a cached workspace by its key, or empty if not present or stale.
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

// reserveWorkspace increments the reference count for an existing workspace or reserves a pending slot.
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

// cancelWorkspaceReservation decrements or releases a pending workspace reservation when clone fails.
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

// isGitRepoPublic checks if the repository is publicly accessible without authentication.
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

// isGitTokenPresent checks if an authentication token is configured for the git URL.
func isGitTokenPresent(gitURL giturl.IGitAPI) bool {
	if token := gitURL.GetToken(); token == "" {
		return false
	}
	return true
}

// getProviderError returns an appropriate missing token error for the git provider.
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

// cloneRepo clones a repository to a local temporary directory and returns the directory.
// depthOpt optionally specifies the clone depth (defaults to DefaultGitCloneDepth = 1 for tip only, 0 for full history).
func cloneRepo(gitURL giturl.IGitAPI, depthOpt ...int) (string, error) {
	depth := DefaultGitCloneDepth
	if len(depthOpt) > 0 {
		depth = depthOpt[0]
	}

	// This is a process-wide go-git setting. Configure it once before any
	// clone starts so different repositories can be cloned concurrently
	// without racing on transport.UnsupportedCapabilities.
	gitTransportOnce.Do(func() {
		transport.UnsupportedCapabilities = []capability.Capability{
			capability.ThinPack,
		}
	})

	cloneURL := gitURL.GetHttpCloneURL()
	commitSHA := extractCommitSHA(gitURL)
	effectiveDepth := depth
	if commitSHA != "" {
		effectiveDepth = 0
	} else if effectiveDepth < 0 {
		effectiveDepth = DefaultGitCloneDepth
	}

	key := repoWorkspaceKey(gitURL, effectiveDepth)
	baseKey := repoBaseKey(gitURL)
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
		if commitSHA != "" {
			// Raw commit SHAs cannot be fetched via branch references (refs/heads/<sha>).
			// Fall back to a full clone (Depth = 0) and check out the commit SHA in the worktree.
			cloneOpts.Depth = 0
		} else {
			cloneOpts.Depth = effectiveDepth
			if cloneOpts.Depth > 0 {
				cloneOpts.SingleBranch = true
			}
			if gitURL.GetBranchName() != "" {
				cloneOpts.ReferenceName = plumbing.NewBranchReferenceName(gitURL.GetBranchName())
				cloneOpts.SingleBranch = true
			}
		}

		// Actual clone
		repo, err := plainClone(tmpDir, false, &cloneOpts)
		if err != nil {
			return "", fmt.Errorf("failed to clone %s: %w", gitURL.GetRepoName(), err)
		}

		if commitSHA != "" && repo != nil {
			hash := plumbing.NewHash(commitSHA)
			if _, err := repo.CommitObject(hash); err != nil {
				rem, remErr := repo.Remote("origin")
				if remErr != nil {
					return "", fmt.Errorf("failed to get origin remote for %s: %w", gitURL.GetRepoName(), remErr)
				}
				fetchErr := rem.Fetch(&git.FetchOptions{
					Auth:     auth,
					RefSpecs: []config.RefSpec{config.RefSpec(fmt.Sprintf("%s:%s", commitSHA, commitSHA))},
				})
				if fetchErr != nil && !errors.Is(fetchErr, git.NoErrAlreadyUpToDate) {
					return "", fmt.Errorf("failed to fetch commit %s in %s: %w", commitSHA, gitURL.GetRepoName(), fetchErr)
				}
			}

			wt, err := repo.Worktree()
			if err != nil {
				return "", fmt.Errorf("failed to get worktree for %s: %w", gitURL.GetRepoName(), err)
			}
			if err := wt.Checkout(&git.CheckoutOptions{Hash: hash}); err != nil {
				return "", fmt.Errorf("failed to checkout commit %s in %s: %w", commitSHA, gitURL.GetRepoName(), err)
			}
		}

		tmpDirPathsMu.Lock()
		tmpDirPaths[key] = tmpDir
		repoActiveKeys[baseKey] = key
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
func ReleaseClonedRepo(path string, depthOpt ...int) error {
	gitURL, err := giturl.NewGitAPI(path)
	if err != nil {
		return err
	}

	tmpDirPathsMu.Lock()
	baseKey := repoBaseKey(gitURL)
	var key string
	if len(depthOpt) > 0 {
		key = repoWorkspaceKey(gitURL, depthOpt[0])
	} else {
		key = repoActiveKeys[baseKey]
		if key == "" {
			key = repoWorkspaceKey(gitURL, DefaultGitCloneDepth)
			if tmpDirPaths[key] == "" {
				key = baseKey
			}
		}
	}

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
	if repoActiveKeys[baseKey] == key {
		delete(repoActiveKeys, baseKey)
	}
	tmpDirPathsMu.Unlock()

	if err := os.RemoveAll(workspace); err != nil {
		return fmt.Errorf("failed to remove cloned repository %s: %w", workspace, err)
	}
	return nil
}

// CloneGitRepo clone git repository with optional depth (defaults to DefaultGitCloneDepth = 1 for tip only).
// Set depth to 0 for full commit history.
func CloneGitRepo(path *string, depthOpt ...int) (string, error) {
	depth := DefaultGitCloneDepth
	if len(depthOpt) > 0 {
		depth = depthOpt[0]
	}
	var clonedDir string

	gitURL, err := giturl.NewGitAPI(*path)
	if err != nil {
		return "", err
	}

	// Clone git repository if needed
	logger.L().Start("cloning", helpers.String("repository url", gitURL.GetURL().String()))

	clonedDir, err = cloneRepo(gitURL, depth)
	if err != nil {
		logger.L().StopError("failed to clone git repo", helpers.String("url", gitURL.GetURL().String()), helpers.Error(err))
		return "", fmt.Errorf("failed to clone git repo '%s',  %w", gitURL.GetURL().String(), err)
	}
	*path = clonedDir

	logger.L().StopSuccess("Done accessing remote repo")

	return clonedDir, nil
}

// GetClonedPath returns the temporary workspace directory for a cloned repository URL.
func GetClonedPath(path string) string {
	gitURL, err := giturl.NewGitAPI(path)
	if err != nil {
		return ""
	}

	tmpDirPathsMu.Lock()
	defer tmpDirPathsMu.Unlock()

	baseKey := repoBaseKey(gitURL)
	key := repoActiveKeys[baseKey]
	if key == "" {
		key = repoWorkspaceKey(gitURL, DefaultGitCloneDepth)
		if tmpDirPaths[key] == "" {
			key = baseKey
		}
	}

	p := tmpDirPaths[key]
	if p == "" {
		return ""
	}
	if info, err := os.Stat(p); err != nil || !info.IsDir() {
		delete(tmpDirPaths, key)
		delete(tmpDirRefs, key)
		delete(repoActiveKeys, baseKey)
		return ""
	}
	return p
}
