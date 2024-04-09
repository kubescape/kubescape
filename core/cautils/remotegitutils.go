package cautils

import (
	"errors"
	"fmt"
	nethttp "net/http"
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	giturl "github.com/kubescape/go-git-url"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

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

	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary directory: %w", err)
	}

	// Get the URL to clone
	cloneURL := gitURL.GetHttpCloneURL()

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

	*path = filepath.Join(clonedDir, gitURL.GetPath())
	logger.L().StopSuccess("Done accessing local objects")

	return clonedDir, nil
}
