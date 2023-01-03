package cautils

import (
	"fmt"
	"path"
	"strings"
	"time"

	gitv5 "github.com/go-git/go-git/v5"
	configv5 "github.com/go-git/go-git/v5/config"
	plumbingv5 "github.com/go-git/go-git/v5/plumbing"
	objectv5 "github.com/go-git/go-git/v5/plumbing/object"
	"github.com/kubescape/go-git-url/apis"
)

type LocalGitRepository struct {
	goGitRepo        *gitv5.Repository
	head             *plumbingv5.Reference
	config           *configv5.Config
	fileToLastCommit map[string]*objectv5.Commit
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

	l := &LocalGitRepository{
		goGitRepo: goGitRepo,
		head:      head,
		config:    config,
	}

	return l, nil
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
	ref, err := g.goGitRepo.Head()
	if err != nil {
		return nil, err
	}
	commit, err := g.goGitRepo.CommitObject(ref.Hash())
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

func (g *LocalGitRepository) getAllCommits() ([]*objectv5.Commit, error) {
	ref, err := g.goGitRepo.Head()
	if err != nil {
		return nil, err
	}
	logItr, err := g.goGitRepo.Log(&gitv5.LogOptions{From: ref.Hash()})
	if err != nil {
		return nil, err
	}

	var allCommits []*objectv5.Commit
	err = logItr.ForEach(func(commit *objectv5.Commit) error {
		if commit != nil {
			allCommits = append(allCommits, commit)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return allCommits, nil
}

func (g *LocalGitRepository) GetFileLastCommit(filePath string) (*apis.Commit, error) {
	if len(g.fileToLastCommit) == 0 {
		filePathToCommitTime := map[string]time.Time{}
		filePathToCommit := map[string]*objectv5.Commit{}
		allCommits, _ := g.getAllCommits()

		// builds a map of all files to their last commit
		for _, commit := range allCommits {
			// Ignore merge commits (2+ parents)
			if commit.NumParents() <= 1 {
				tree, err := commit.Tree()
				if err != nil {
					continue
				}

				// ParentCount can be either 1 or 0 (initial commit)
				// In case it's the initial commit, prevTree is nil
				var prevTree *objectv5.Tree
				if commit.NumParents() == 1 {
					prevCommit, _ := commit.Parent(0)
					prevTree, err = prevCommit.Tree()
					if err != nil {
						continue
					}
				}

				changes, err := prevTree.Diff(tree)
				if err != nil {
					continue
				}

				for _, change := range changes {
					deltaFilePath := change.To.Name
					commitTime := commit.Author.When

					// In case we have the commit information for the file which is not the latest - we override it
					if currentCommitTime, exists := filePathToCommitTime[deltaFilePath]; exists {
						if currentCommitTime.Before(commitTime) {
							filePathToCommitTime[deltaFilePath] = commitTime
							filePathToCommit[deltaFilePath] = commit
						}
					} else {
						filePathToCommitTime[deltaFilePath] = commitTime
						filePathToCommit[deltaFilePath] = commit
					}
				}
			}
		}
		g.fileToLastCommit = filePathToCommit
	}

	if relevantCommit, exists := g.fileToLastCommit[filePath]; exists {
		return g.getCommit(relevantCommit), nil
	}

	return nil, fmt.Errorf("failed to get commit information for file: %s", filePath)
}

func (g *LocalGitRepository) getCommit(commit *objectv5.Commit) *apis.Commit {
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
	}
}

func (g *LocalGitRepository) GetRootDir() (string, error) {
	wt, err := g.goGitRepo.Worktree()
	if err != nil {
		return "", fmt.Errorf("failed to get repo root")
	}

	return wt.Filesystem.Root(), nil
}
