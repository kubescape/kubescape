package resourcehandler

import (
	"fmt"
	"path"
	"strings"

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
	date        string
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

func (g *LocalGitRepository) GetOriginUrl() string {
	branchName := g.GetBranchName()
	if branchRef, branchFound := g.config.Branches[branchName]; branchFound {
		remoteName := branchRef.Remote
		return g.config.Remotes[remoteName].URLs[0]
	}

	const defaultRemoteName string = "origin"
	return g.config.Remotes[defaultRemoteName].URLs[0]
}

func (g *LocalGitRepository) GetName() string {
	originUrl := g.GetOriginUrl()
	baseName := path.Base(originUrl)
	// remove .git
	return strings.TrimSuffix(baseName, ".git")
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
		date:        commit.Author.When.String(),
	}, nil
}
