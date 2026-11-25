package ghworkflows

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// The privileged caller must use a pinned shared action without checking out
// contributor code. Behavioral tests live beside the shared action.
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
		"contents": "read", "issues": "write", "pull-requests": "write", "checks": "write",
	}, job.Permissions)
	require.Len(t, job.Steps, 1)
	step := job.Steps[0]
	require.Empty(t, step.Run, "privileged caller must not execute shell snippets")
	require.Regexp(t, `^kubescape/workflows/\.github/actions/contribution-policy@[0-9a-f]{40}$`, step.Uses)
	require.Equal(t, map[string]string{"start": "${{ vars.CONTRIBUTION_POLICY_START }}"}, step.With)
}
