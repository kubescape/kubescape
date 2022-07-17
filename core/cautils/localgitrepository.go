package cautils

import (
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/armosec/go-git-url/apis"
	gitv5 "github.com/go-git/go-git/v5"
	configv5 "github.com/go-git/go-git/v5/config"
	plumbingv5 "github.com/go-git/go-git/v5/plumbing"
	git2go "github.com/libgit2/git2go/v33"
)

type LocalGitRepository struct {
	goGitRepo        *gitv5.Repository
	git2GoRepo       *git2go.Repository
	head             *plumbingv5.Reference
	config           *configv5.Config
	fileToLastCommit map[string]*git2go.Commit
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

	git2GoRepo, err := git2go.OpenRepository(path)
	if err != nil {
		return nil, err
	}

	return &LocalGitRepository{
		goGitRepo:  goGitRepo,
		head:       head,
		config:     config,
		git2GoRepo: git2GoRepo,
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

func (g *LocalGitRepository) getAllCommits() ([]*git2go.Commit, error) {
	logItr, itrErr := g.git2GoRepo.Walk()
	if itrErr != nil {

		return nil, itrErr
	}

	pushErr := logItr.PushHead()
	if pushErr != nil {
		return nil, pushErr
	}

	var allCommits []*git2go.Commit
	err := logItr.Iterate(func(commit *git2go.Commit) bool {
		if commit != nil {
			allCommits = append(allCommits, commit)
			return true
		}
		return false
	})

	if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	return allCommits, nil
}

func (g *LocalGitRepository) GetFileLastCommit(filePath string) (*apis.Commit, error) {
	if g.fileToLastCommit == nil {
		filePathToCommitTime := map[string]time.Time{}
		filePathToCommit := map[string]*git2go.Commit{}
		allCommits, _ := g.getAllCommits()

		// builds a map of all files to their last commit
		for _, commit := range allCommits {
			// Ignore merge commits (2+ parents)
			if commit.ParentCount() <= 1 {
				tree, err := commit.Tree()
				if err != nil {
					continue
				}

				// ParentCount can be either 1 or 0 (initial commit)
				// In case it's the initial commit, prevTree is nil
				var prevTree *git2go.Tree
				if commit.ParentCount() == 1 {
					prevCommit := commit.Parent(0)
					prevTree, err = prevCommit.Tree()
					if err != nil {
						continue
					}
				}

				diff, err := g.git2GoRepo.DiffTreeToTree(prevTree, tree, nil)
				if err != nil {
					continue
				}

				numDeltas, err := diff.NumDeltas()
				if err != nil {
					continue
				}

				for i := 0; i < numDeltas; i++ {
					delta, err := diff.Delta(i)
					if err != nil {
						continue
					}

					deltaFilePath := delta.NewFile.Path
					commitTime := commit.Author().When

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

func (g *LocalGitRepository) getCommit(commit *git2go.Commit) *apis.Commit {
	return &apis.Commit{
		SHA: commit.Id().String(),
		Author: apis.Committer{
			Name:  commit.Author().Name,
			Email: commit.Author().Email,
			Date:  commit.Author().When,
		},
		Message:   commit.Message(),
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
