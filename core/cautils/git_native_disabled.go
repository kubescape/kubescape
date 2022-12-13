//go:build !gitenabled

package cautils

import (
	"errors"

	"github.com/kubescape/go-git-url/apis"
)

var ErrFatalNotSupportedByBuild = errors.New(`git scan not supported by this build. Build with tag "gitenabled" to enable the git scan feature`)

type gitRepository struct {
}

func newGitRepository(root string) (*gitRepository, error) {
	return &gitRepository{}, ErrWarnNotSupportedByBuild
}

func (g *gitRepository) GetFileLastCommit(filePath string) (*apis.Commit, error) {
	return nil, ErrFatalNotSupportedByBuild
}
