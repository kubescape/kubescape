package cautils

import (
	"testing"

	giturl "github.com/kubescape/go-git-url"
	"github.com/stretchr/testify/require"
)

func TestEnsureRemoteParsed(t *testing.T) {
	const remote = "git@gitlab.com:foobar/gitlab-tests/sample-project.git"

	require.NotPanics(t, func() {
		_, _ = giturl.NewGitURL(remote)
	})
}
