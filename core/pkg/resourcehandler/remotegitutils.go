package resourcehandler

import (
	"fmt"
	"os"

	giturl "github.com/armosec/go-git-url"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

// cloneRepo clones a repository to a local temporary directory and returns the directory
func cloneRepo(gitURL giturl.IGitURL) (string, error) {

	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary directory: %w", err)
	}

	// Clone option
	cloneURL := gitURL.GetHttpCloneURL()
	cloneOpts := git.CloneOptions{URL: cloneURL}
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
