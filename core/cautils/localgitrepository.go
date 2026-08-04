package cautils

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"

	gitv5 "github.com/go-git/go-git/v5"
	configv5 "github.com/go-git/go-git/v5/config"
	plumbingv5 "github.com/go-git/go-git/v5/plumbing"
	"github.com/kubescape/go-git-url/apis"
)

type LocalGitRepository struct {
	*gitRepository
	goGitRepo *gitv5.Repository
	head      *plumbingv5.Reference
	config    *configv5.Config
}

// worktreeRoot resolves the repository's worktree root. It is a package-level
// var (rather than a direct l.GetRootDir() call) purely so tests can swap in
// a failing stub to exercise the defensive nil-on-error handling below: with
// the pinned go-git version, Worktree() only fails when the repository was
// opened without a worktree filesystem, which PlainOpenWithOptions's
// DetectDotGit walk does not yield while Head()/Config() still resolve — so
// no real on-disk fixture can reach that branch today.
var worktreeRoot = (*LocalGitRepository).GetRootDir

func NewLocalGitRepository(path string) (*LocalGitRepository, error) {
	goGitRepo, err := gitv5.PlainOpenWithOptions(path, &gitv5.PlainOpenOptions{DetectDotGit: true, EnableDotGitCommonDir: true})
	if err != nil {
		return nil, err
	}

	head, err := goGitRepo.Head()
	if err != nil {
		return nil, err
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

	repoRoot, err := worktreeRoot(l)
	if err != nil {
		return nil, err
	}

	// newGitRepository (git_native_disabled.go) never actually returns a
	// non-nil error today; this is propagated defensively rather than
	// ignored so NewLocalGitRepository can't return a partially
	// initialized *LocalGitRepository if that ever changes.
	gitRepository, err := newGitRepository(repoRoot)
	if err != nil {
		return nil, err
	}
	l.gitRepository = gitRepository

	return l, nil
}

// GetBranchName get current branch name
func (g *LocalGitRepository) GetBranchName() string {
	if !g.head.Name().IsBranch() {
		return ""
	}
	return g.head.Name().Short()
}

// GetRemoteUrl get default remote URL
func (g *LocalGitRepository) GetRemoteUrl() (string, error) {
	branchName := g.GetBranchName()
	if branchRef, branchFound := g.config.Branches[branchName]; branchFound {
		remoteName := branchRef.Remote
		// branchRef.Remote can be a reference to a config.Remotes entry or directly a gitUrl
		if _, found := g.config.Remotes[remoteName]; !found {
			return remoteName, nil
		}
		if len(g.config.Remotes[remoteName].URLs) == 0 {
			return "", fmt.Errorf("expected to find URLs for remote '%s', branch '%s'", remoteName, branchName)
		}
		return g.config.Remotes[remoteName].URLs[0], nil
	}

	const defaultRemoteName string = "origin"
	defaultRemote, ok := g.config.Remotes[defaultRemoteName]
	if !ok {
		return "", fmt.Errorf("did not find a default remote with name '%s'", defaultRemoteName)
	} else if len(defaultRemote.URLs) == 0 {
		return "", fmt.Errorf("expected to find URLs for remote '%s'", defaultRemoteName)
	}
	return defaultRemote.URLs[0], nil
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
		Message: commit.Message,
		Committer: apis.Committer{
			Name:  commit.Committer.Name,
			Email: commit.Committer.Email,
			Date:  commit.Committer.When,
		},
		Files: []apis.Files{},
	}, nil
}

// GetGitRootDir returns the root directory of the git repository containing path.
// It deliberately does not go through NewLocalGitRepository: locating the root must
// not depend on the branch and remote metadata that constructor demands, which CI
// checkouts routinely lack even though the repository every reported path is
// relative to is right there.
func GetGitRootDir(path string) (string, error) {
	goGitRepo, err := gitv5.PlainOpenWithOptions(path, &gitv5.PlainOpenOptions{DetectDotGit: true, EnableDotGitCommonDir: true})
	if err != nil {
		return "", err
	}

	worktree, err := goGitRepo.Worktree()
	if err != nil {
		return "", fmt.Errorf("failed to get repo root: %w", err)
	}

	return worktree.Filesystem.Root(), nil
}

// FileScanRootPath returns the root a single-file scan's reported paths are relative to:
// the repository root when the file sits inside a worktree, and the file's own directory
// otherwise. The File scanning target records the scanned file rather than a root, so
// every consumer has to derive the anchor from the same rule or a file scan's relative
// paths resolve against different bases in `fix` and in the printers.
func FileScanRootPath(filePath string) string {
	if root, err := GetGitRootDir(filePath); err == nil {
		return root
	}
	return filepath.Dir(filePath)
}

// ScanRootPath returns the root that paths reported for input are relative to: the
// repository root when input sits inside a worktree, and input's own absolute path
// otherwise. Scan metadata and the resource sources built in the file loader must
// derive their anchor the same way, or the report's base path and its resources'
// relative paths no longer compose.
func ScanRootPath(input string) string {
	absPath := getAbsPath(input)
	if root, err := GetGitRootDir(absPath); err == nil {
		return root
	}
	return absPath
}

// GetRootDir returns the root directory of the repository's worktree
func (g *LocalGitRepository) GetRootDir() (string, error) {
	wt, err := g.goGitRepo.Worktree()
	if err != nil {
		return "", fmt.Errorf("failed to get repo root")
	}

	return wt.Filesystem.Root(), nil
}
