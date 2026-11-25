package ghworkflows

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// A workflow with write permissions must execute the trusted workflow revision,
// never the contributor's PR head. Tests for the policy itself run separately
// in the unprivileged repo-hygiene workflow.
func TestContributionPolicyTrustBoundary(t *testing.T) {
	content := workflowFiles(t)["contribution-policy.yaml"]
	require.NotEmpty(t, content)
	var workflow struct {
		On          map[string]interface{} `yaml:"on"`
		Permissions map[string]string      `yaml:"permissions"`
		Concurrency struct {
			Group  string `yaml:"group"`
			Queue  string `yaml:"queue"`
			Cancel bool   `yaml:"cancel-in-progress"`
		} `yaml:"concurrency"`
		Jobs map[string]struct {
			If          string            `yaml:"if"`
			Permissions map[string]string `yaml:"permissions"`
			Steps       []struct {
				Uses string            `yaml:"uses"`
				Run  string            `yaml:"run"`
				With map[string]string `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal(content, &workflow))
	require.Empty(t, workflow.Permissions)
	require.Contains(t, workflow.On, "pull_request_target")
	require.Contains(t, workflow.On, "issues")
	require.Contains(t, workflow.On, "issue_comment")
	require.Contains(t, workflow.On, "schedule")
	require.Equal(t, "contribution-policy", workflow.Concurrency.Group)
	require.Equal(t, "max", workflow.Concurrency.Queue)
	require.False(t, workflow.Concurrency.Cancel)
	job := workflow.Jobs["policy"]
	require.Contains(t, job.If, "vars.CONTRIBUTION_POLICY_START != ''")
	require.Equal(t, map[string]string{
		"contents": "read", "issues": "write", "pull-requests": "write", "statuses": "write",
	}, job.Permissions)
	checkoutFound := false
	for _, step := range job.Steps {
		require.Empty(t, step.Run, "privileged workflow should use the reviewed script, not shell snippets")
		require.Regexp(t, `^[\w-]+/[\w-]+@[0-9a-f]{40}$`, step.Uses)
		if strings.HasPrefix(step.Uses, "actions/checkout@") {
			checkoutFound = true
			require.Equal(t, "${{ github.workflow_sha }}", step.With["ref"])
			require.Equal(t, "false", step.With["persist-credentials"])
		} else {
			require.True(t, strings.HasPrefix(step.Uses, "actions/github-script@"))
			require.Contains(t, step.With["script"], "require('./.github/scripts/contribution-policy.cjs')")
			require.NotContains(t, step.With["script"], "${{", "event text must enter through context, never script interpolation")
		}
	}
	require.True(t, checkoutFound)
	hygiene := string(workflowFiles(t)["repo-hygiene.yaml"])
	require.Contains(t, hygiene, "node --test .github/scripts/tests/contribution-policy.test.cjs")
	_, err := os.Stat(filepath.Join(workflowsDir(t), "..", "scripts", "tests", "contribution-policy.test.cjs"))
	require.NoError(t, err)
}
