//go:build gitenabled
package cautils

import (
	"fmt"
	"time"

	"github.com/kubescape/go-git-url/apis"
	git2go "github.com/libgit2/git2go/v33"
)

type gitRepository struct {
	git2GoRepo       *git2go.Repository
	fileToLastCommit map[string]*git2go.Commit
}

func newGitRepository(root string) (*gitRepository, error) {
	git2GoRepo, err := git2go.OpenRepository(root)
	if err != nil {
		return nil, err
	}

	return &gitRepository{
		git2GoRepo: git2GoRepo,
	}, nil
}

func (g *gitRepository) GetFileLastCommit(filePath string) (*apis.Commit, error) {
	if len(g.fileToLastCommit) == 0 {
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

func (g *gitRepository) getAllCommits() ([]*git2go.Commit, error) {
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

func (g *gitRepository) getCommit(commit *git2go.Commit) *apis.Commit {
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
