//go:build windows
// +build windows

package cautils

import (
	"fmt"
	"path"
	"strings"

	"github.com/armosec/go-git-url/apis"
	gitv5 "github.com/go-git/go-git/v5"
	configv5 "github.com/go-git/go-git/v5/config"
	plumbingv5 "github.com/go-git/go-git/v5/plumbing"
)

type LocalGitRepository struct {
	goGitRepo *gitv5.Repository
	head      *plumbingv5.Reference
	config    *configv5.Config
}

func NewLocalGitRepository(path string) (*LocalGitRepository, error) {
	goGitRepo, err := gitv5.PlainOpenWithOptions(path, &gitv5.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return nil, err
	}

	head, err := goGitRepo.Head()
	if err != nil {
		return nil, err
	}

	if !head.Name().IsBranch() {
		return nil, fmt.Errorf("current HEAD reference is not a branch")
	}

	config, err := goGitRepo.Config()
	if err != nil {
		return nil, err
	}

	if len(config.Remotes) == 0 {
		return nil, fmt.Errorf("no remotes found")
	}

	return &LocalGitRepository{
		goGitRepo: goGitRepo,
		head:      head,
		config:    config,
	}, nil
}

// GetBranchName get current branch name
func (g *LocalGitRepository) GetBranchName() string {
	return g.head.Name().Short()
}

// GetRemoteUrl get default remote URL
func (g *LocalGitRepository) GetRemoteUrl() (string, error) {
	branchName := g.GetBranchName()
	if branchRef, branchFound := g.config.Branches[branchName]; branchFound {
		remoteName := branchRef.Remote
		if len(g.config.Remotes[remoteName].URLs) == 0 {
			return "", fmt.Errorf("expected to find URLs for remote '%s', branch '%s'", remoteName, branchName)
		}
		return g.config.Remotes[remoteName].URLs[0], nil
	}

	const defaultRemoteName string = "origin"
	if len(g.config.Remotes[defaultRemoteName].URLs) == 0 {
		return "", fmt.Errorf("expected to find URLs for remote '%s'", defaultRemoteName)
	}
	return g.config.Remotes[defaultRemoteName].URLs[0], nil
}

// GetName get origin name without the .git suffix
func (g *LocalGitRepository) GetName() (string, error) {
	originUrl, err := g.GetRemoteUrl()
	if err != nil {
		return "", err
	}
	baseName := path.Base(originUrl)
	// remove .git
	return strings.TrimSuffix(baseName, ".git"), nil
}

// GetLastCommit get latest commit object
func (g *LocalGitRepository) GetLastCommit() (*apis.Commit, error) {
	cIter, err := g.goGitRepo.Log(&gitv5.LogOptions{})
	if err != nil {
		return nil, err
	}

	commit, err := cIter.Next()
	defer cIter.Close()
	if err != nil {
		return nil, err
	}

	return &apis.Commit{
		SHA: commit.Hash.String(),
		Author: apis.Committer{
			Name:  commit.Author.Name,
			Email: commit.Author.Email,
			Date:  commit.Author.When,
		},
		Message:   commit.Message,
		Committer: apis.Committer{},
		Files:     []apis.Files{},
	}, nil
}

func (g *LocalGitRepository) GetFileLastCommit(filePath string) (*apis.Commit, error) {
	return nil, nil
}

func (g *LocalGitRepository) GetRootDir() (string, error) {
	wt, err := g.goGitRepo.Worktree()
	if err != nil {
		return "", fmt.Errorf("failed to get repo root")
	}

	return wt.Filesystem.Root(), nil
}
