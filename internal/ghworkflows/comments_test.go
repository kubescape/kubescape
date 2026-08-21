// This test guards a "pwn request" regression: comments.yaml's pr_agent job
// ran on `issue_comment` with `issues: write` and `pull-requests: write` and
// no filter on who left the comment. issue_comment always evaluates against
// the base repository's token, even for a comment on a fork's pull request,
// so any commenter - not a collaborator, not even a contributor - could drive
// a write-scoped bot that feeds their comment and the PR diff to an LLM and
// posts its output back with that token.
//
// Nothing failed. The job ran exactly as designed for every comment; the only
// thing missing was a check on who was allowed to trigger it.
package ghworkflows

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	commentsWorkflowName = "comments.yaml"
	prAgentJobName       = "pr_agent"
)

// commentsWorkflow is the subset of comments.yaml these tests assert on.
// Job-level `permissions` is a mapping, decoded the same way releaseWorkflow
// decodes it above - Go field names cannot hold the hyphen in
// "pull-requests", so a map sidesteps needing a struct tag for it.
type commentsWorkflow struct {
	Jobs map[string]struct {
		If          string            `yaml:"if"`
		Permissions map[string]string `yaml:"permissions"`
	} `yaml:"jobs"`
}

// TestPRAgentJobRequiresTrustedCommenter is the direct regression test. It
// asserts both halves of the shape, not just one: permissions alone would
// fire this guard on a job that no longer needs it, and an `if:` alone would
// not explain why one is required at all.
func TestPRAgentJobRequiresTrustedCommenter(t *testing.T) {
	var workflow commentsWorkflow
	loadWorkflow(t, commentsWorkflowName, &workflow)

	job, ok := workflow.Jobs[prAgentJobName]
	require.Truef(t, ok, "%s has no %q job; this guard needs updating to follow it",
		commentsWorkflowName, prAgentJobName)

	assert.Equalf(t, "write", job.Permissions["issues"],
		"%s's %q job no longer holds issues: write; if that's intentional this guard can be relaxed, "+
			"but if it still writes to issues it still needs the trust gate below",
		commentsWorkflowName, prAgentJobName)
	assert.Equalf(t, "write", job.Permissions["pull-requests"],
		"%s's %q job no longer holds pull-requests: write", commentsWorkflowName, prAgentJobName)

	require.NotEmptyf(t, job.If,
		"%s's %q job runs on `issue_comment` with issues/pull-requests write access and no `if:` gate - "+
			"any commenter, not just a collaborator, can drive a write-scoped bot that feeds their comment "+
			"and the PR diff to an LLM and posts its output back with that token",
		commentsWorkflowName, prAgentJobName)

	assert.Containsf(t, job.If, "author_association",
		"%s's %q job gates on something other than the commenter's association with the repository; "+
			"author_association is GitHub's own server-computed field and the only one of these inputs "+
			"a commenter cannot forge", commentsWorkflowName, prAgentJobName)

	for _, trusted := range []string{"OWNER", "MEMBER", "COLLABORATOR"} {
		assert.Containsf(t, job.If, trusted,
			"%s's %q job's trust gate no longer allows %q commenters",
			commentsWorkflowName, prAgentJobName, trusted)
	}
}
