package cautils

import (
	"crypto/sha256"
	"errors"
	"fmt"
	nethttp "net/http"
	"os"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	giturl "github.com/kubescape/go-git-url"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

var tmpDirPaths map[string]string

func hashRepoURL(repoURL string) string {
	h := sha256.New()
	h.Write([]byte(repoURL))
	return string(h.Sum(nil))
}

func getDirPath(repoURL string) string {
	if tmpDirPaths == nil {
		return ""
	}
	return tmpDirPaths[hashRepoURL(repoURL)]
}

// Create a temporary directory this function is called once
func createTempDir(repoURL string) (string, error) {
	tmpDirPath := getDirPath(repoURL)
	if tmpDirPath != "" {
		return tmpDirPath, nil
	}
	// create temp directory
	tmpDir, err := os.MkdirTemp("", "")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary directory: %w", err)
	}
	if tmpDirPaths == nil {
		tmpDirPaths = make(map[string]string)
	}
	tmpDirPaths[hashRepoURL(repoURL)] = tmpDir

	return tmpDir, nil
}

// To Check if the given repository is Public(No Authentication needed), send a HTTP GET request to the URL
// If response code is 200, the repository is Public.
func isGitRepoPublic(u string) bool {
	resp, err := nethttp.Get(u) //nolint:gosec
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
	cloneURL := gitURL.GetHttpCloneURL()

	// Check if directory exists
	if p := getDirPath(cloneURL); p != "" {
		// directory exists, meaning this repo was cloned
		return p, nil
	}
	// Get the URL to clone

	// Create temp directory
	tmpDir, err := createTempDir(cloneURL)
	if err != nil {
		return "", err
	}

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

	// For Azure repo cloning
	transport.UnsupportedCapabilities = []capability.Capability{
		capability.ThinPack,
	}

	// Clone option
	cloneOpts := git.CloneOptions{URL: cloneURL, Auth: auth}
	if gitURL.GetBranchName() != "" {
		cloneOpts.ReferenceName = plumbing.NewBranchReferenceName(gitURL.GetBranchName())
		cloneOpts.SingleBranch = true
	}

	// Actual clone
	_, err = git.PlainClone(tmpDir, false, &cloneOpts)
	if err != nil {
		return "", fmt.Errorf("failed to clone %s. %w", gitURL.GetRepoName(), err)
	}
	// tmpDir = filepath.Join(tmpDir, gitURL.GetRepoName())
	tmpDirPaths[hashRepoURL(cloneURL)] = tmpDir

	return tmpDir, nil
}

// CloneGitRepo clone git repository
func CloneGitRepo(path *string) (string, error) {
	var clonedDir string

	gitURL, err := giturl.NewGitAPI(*path)
	if err != nil {
		return "", nil
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

	return getDirPath(gitURL.GetHttpCloneURL())
}
