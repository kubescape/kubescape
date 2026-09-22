// This test guards a merge-skew regression: nothing built or tested master.
//
// 00-pr-scanner.yaml ran on pull_request only, 02-release.yaml runs on release
// tags, and scorecard.yml analyses the repository rather than compiling it. A
// pull_request run builds the PR merged into the base as the base stood when
// the run started, so two PRs that never saw each other could each be green,
// both merge, and leave master broken with no check having failed anywhere.
//
// That is what happened: two pagination fixes merged seventeen seconds apart,
// each adding an identical test helper to the same package, and the duplicate
// declaration broke `go test ./...` for the whole repository. Nothing reported
// it, because nothing was watching master. The first sign was every subsequent
// pull request going red on a redeclaration in two files its author had never
// opened, which reads as "my PR is broken" rather than "the base is broken".
//
// These tests assert the push trigger still exists, still names the branch
// scorecard.yml pins, still ignores exactly the paths the pull_request trigger
// ignores, and still leaves its runs alone once started - and that widening the
// trigger did not also start dispatching the private E2E suite on every merge.
//
// Deliberately test-only: this is a repository-hygiene guard, so it adds no
// production surface.
package ghworkflows

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// prScannerWorkflowName is the entrypoint that builds and tests the code.
	prScannerWorkflowName = "00-pr-scanner.yaml"

	// systemTestsJobName dispatches the E2E suite to a private repository and
	// polls it for up to an hour. It is a review gate on a proposed change, so
	// it has no business running on a merge.
	systemTestsJobName = "run-system-tests"
)

// prScannerWorkflow is the subset of 00-pr-scanner.yaml these tests assert on.
// gopkg.in/yaml.v3 follows the YAML 1.2 core schema, so `on:` unmarshals as the
// plain string "on" and the struct tag below matches it.
type prScannerWorkflow struct {
	On struct {
		PullRequest struct {
			PathsIgnore []string `yaml:"paths-ignore"`
		} `yaml:"pull_request"`
		Push struct {
			Branches    []string `yaml:"branches"`
			PathsIgnore []string `yaml:"paths-ignore"`
		} `yaml:"push"`
	} `yaml:"on"`
	Concurrency struct {
		// CancelInProgress is a string rather than a bool: it carries a
		// ${{ }} expression, which a bool field would fail to decode.
		CancelInProgress string `yaml:"cancel-in-progress"`
	} `yaml:"concurrency"`
	Jobs map[string]struct {
		If string `yaml:"if"`
	} `yaml:"jobs"`
}

func loadPRScanner(t *testing.T) prScannerWorkflow {
	t.Helper()

	var workflow prScannerWorkflow
	loadWorkflow(t, prScannerWorkflowName, &workflow)
	return workflow
}

// TestPRScannerRunsOnPushToDefaultBranch is the direct regression test. The
// branch is compared against scorecard.yml rather than hard-coded here, because
// scorecard.yml is the only machine-readable statement of the default branch in
// the repository - the same source TestReadmeDocumentsTheRealDefaultBranch uses.
// A rename that updated one and not the other would otherwise leave this
// trigger pointing at a branch nobody merges to, which fails silently.
func TestPRScannerRunsOnPushToDefaultBranch(t *testing.T) {
	workflow := loadPRScanner(t)

	branches := workflow.On.Push.Branches
	require.NotEmptyf(t, branches,
		"%s no longer runs on push; a pull_request run only proves the PR was green against the base as it "+
			"stood when the run started, so two PRs that never saw each other can each pass and still break "+
			"the branch when both land, with nothing failing along the way",
		prScannerWorkflowName)

	assert.Containsf(t, branches, defaultBranch(t),
		"%s runs on push to %v but %s pins %q as the default branch; the branch everyone merges to is the "+
			"one that has to be built", prScannerWorkflowName, branches, scorecardWorkflow, defaultBranch(t))
}

// TestPRScannerPushAndPullRequestIgnoreTheSamePaths keeps the two filters from
// drifting apart. They answer the same question - can this change affect
// whether the code builds - so a path worth skipping before a merge is worth
// skipping after it. Drift in either direction is a bug: a path added only to
// the push list stops master being built for changes a PR still gets checked
// for, and one added only to the pull_request list spends CI on merges whose
// PRs were skipped.
func TestPRScannerPushAndPullRequestIgnoreTheSamePaths(t *testing.T) {
	workflow := loadPRScanner(t)

	require.NotEmptyf(t, workflow.On.PullRequest.PathsIgnore,
		"%s declares no pull_request paths-ignore; this guard compares the two lists and needs both",
		prScannerWorkflowName)

	assert.ElementsMatchf(t, workflow.On.PullRequest.PathsIgnore, workflow.On.Push.PathsIgnore,
		"%s's push and pull_request paths-ignore lists have drifted apart (pull_request: %v, push: %v); "+
			"both decide whether a change can affect the build, so they have to say the same thing",
		prScannerWorkflowName, workflow.On.PullRequest.PathsIgnore, workflow.On.Push.PathsIgnore)
}

// TestPRScannerDoesNotCancelDefaultBranchRuns guards the other half of the
// trigger. The concurrency group keys on github.ref, which is the same value
// for every push to master, so an unconditional cancel-in-progress would let a
// second merge kill the first merge's run. The merge that broke the branch
// would then carry no verdict at all - the precise state the push trigger
// exists to end - while still looking like it had been checked.
func TestPRScannerDoesNotCancelDefaultBranchRuns(t *testing.T) {
	workflow := loadPRScanner(t)

	cancel := strings.TrimSpace(workflow.Concurrency.CancelInProgress)
	if cancel == "" {
		return // Absent means runs are never cancelled, which is safe here.
	}

	assert.NotEqualf(t, "true", cancel,
		"%s cancels in-progress runs unconditionally, and its concurrency group keys on github.ref, which "+
			"is identical for every push to the default branch; a second merge would cancel the first "+
			"merge's run and leave it with no verdict. Gate it on the event, e.g. "+
			"cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
		prScannerWorkflowName)
}

// TestSystemTestsDoNotRunOnMerge makes sure widening the trigger did not
// quietly widen what it triggers. The E2E job dispatches to a private
// repository and polls for up to an hour, and derives both its correlation id
// and KS_BRANCH from the head ref - which on a push is just the branch name. It
// is a gate on a proposed change, not a health check on a merged one.
func TestSystemTestsDoNotRunOnMerge(t *testing.T) {
	workflow := loadPRScanner(t)

	job, ok := workflow.Jobs[systemTestsJobName]
	require.Truef(t, ok, "%s has no %q job; this guard needs updating to follow it",
		prScannerWorkflowName, systemTestsJobName)

	assert.Containsf(t, job.If, "github.event_name != 'push'",
		"%s's %q job is not gated against push, so every merge to the default branch would dispatch the "+
			"private E2E suite and poll it for up to an hour, under a branch name that identifies no pull "+
			"request; got %q", prScannerWorkflowName, systemTestsJobName, job.If)
}
