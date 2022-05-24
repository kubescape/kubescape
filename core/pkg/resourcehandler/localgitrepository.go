package resourcehandler

import (
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
)

type LocalGitRepository struct {
	repo   *git.Repository
	head   *plumbing.Reference
	config *config.Config
}

type GitCommit struct {
	hash        string
	authorName  string
	authorEmail string
	message     string
	date        time.Time
}

func NewLocalGitRepository(path string) (*LocalGitRepository, error) {
	gitRepo, err := git.PlainOpen(path)
	if err != nil {
		return nil, err
	}

	head, err := gitRepo.Head()
	if err != nil {
		return nil, err
	}

	if !head.Name().IsBranch() {
		return nil, fmt.Errorf("current HEAD reference is not a branch")
	}

	config, err := gitRepo.Config()
	if err != nil {
		return nil, err
	}

	return &LocalGitRepository{
		repo:   gitRepo,
		head:   head,
		config: config,
	}, nil
}

func (g *LocalGitRepository) GetBranchName() string {
	return g.head.Name().Short()
}

func (g *LocalGitRepository) GetOriginUrl() (string, error) {
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

func (g *LocalGitRepository) GetName() (string, error) {
	originUrl, err := g.GetOriginUrl()
	if err != nil {
		return "", err
	}
	baseName := path.Base(originUrl)
	// remove .git
	return strings.TrimSuffix(baseName, ".git"), nil
}

func (g *LocalGitRepository) GetLastCommit() (*GitCommit, error) {
	return g.GetFileLastCommit("")
}

func (g *LocalGitRepository) GetFileLastCommit(filePath string) (*GitCommit, error) {
	// By default, returns commit information from current HEAD
	logOptions := &git.LogOptions{}

	if filePath != "" {
		logOptions.FileName = &filePath
		logOptions.Order = git.LogOrderCommitterTime
	}

	cIter, err := g.repo.Log(logOptions)
	if err != nil {
		return nil, err
	}

	commit, err := cIter.Next()
	defer cIter.Close()
	if err != nil {
		return nil, err
	}

	return &GitCommit{
		message:     commit.Message,
		hash:        commit.Hash.String(),
		authorName:  commit.Author.Name,
		authorEmail: commit.Author.Email,
		date:        commit.Author.When,
	}, nil
}
