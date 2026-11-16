// Package ghworkflows guards repository hygiene and workflow configuration.
package ghworkflows

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestPublishResultsIsGuardedAgainstForks verifies that the OSPS Baseline
// publisher workflow runs only in the upstream repository. Scheduled workflows
// trigger on forks by default, but only the upstream repository holds OIDC
// publishing rights for the kubescape namespace on hub.grc.store.
func TestPublishResultsIsGuardedAgainstForks(t *testing.T) {
	path := filepath.Join(workflowsDir(t), "publish-results.yml")
	content, ok := workflowFiles(t)["publish-results.yml"]
	require.Truef(t, ok, "missing %s", path)

	var workflow struct {
		Jobs map[string]struct {
			If string `yaml:"if"`
		} `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal(content, &workflow))

	job, ok := workflow.Jobs["publish"]
	require.True(t, ok, "publish-results.yml has no 'publish' job")

	assert.True(t, strings.Contains(job.If, "github.repository == 'kubescape/kubescape'"),
		"publish-results.yml's publish job must be gated to github.repository == 'kubescape/kubescape', "+
			"otherwise scheduled runs execute on forks where OIDC publishing to hub.grc.store fails with 403; got %q", job.If)
}
