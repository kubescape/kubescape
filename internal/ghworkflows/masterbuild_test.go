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
// ignores, and still gives every merge a run of its own that nothing cancels or
// replaces - and that widening the trigger did not also start dispatching the
// private E2E suite on every merge.
//
// Deliberately test-only: this is a repository-hygiene guard, so it adds no
// production surface.
package ghworkflows

import (
	"fmt"
	"strings"
	"testing"
	"unicode"

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
		Group string `yaml:"group"`
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

// TestPRScannerGivesEveryMasterPushItsOwnRun guards the other half of the
// trigger. A concurrency group admits one running and one pending run, and a
// newer arrival replaces the pending one whatever cancel-in-progress says. With
// every push to master in one group, merge A running, B pending and C arriving
// is enough to drop B's run - and if B is the merge that broke the branch, it
// carries no verdict at all while still looking like it had been checked, which
// is the precise state the push trigger exists to end.
//
// So each push has to resolve to a group of its own, and must not be cancelled
// either. This evaluates the workflow's own expressions for a burst of merges
// rather than matching their text, so any spelling that shares a group between
// pushes fails, and any that keeps them apart passes.
func TestPRScannerGivesEveryMasterPushItsOwnRun(t *testing.T) {
	workflow := loadPRScanner(t)

	pushes := []concurrencyEvent{
		masterPush("a1a1a1a", "1001"),
		masterPush("b2b2b2b", "1002"),
		masterPush("c3c3c3c", "1003"),
	}

	seen := map[string]string{}
	for _, push := range pushes {
		group := evalWorkflowTemplate(t, workflow.Concurrency.Group, push)
		if other, ok := seen[group]; ok {
			assert.Failf(t, "master pushes share a concurrency group",
				"%s puts the pushes of %s and %s into the same concurrency group %q; with one running, one "+
					"pending and a third arriving, GitHub replaces the pending run even with cancel-in-progress "+
					"off, so a merge can land with no verdict. Key non-PR runs on something unique per run, "+
					"e.g. github.run_id", prScannerWorkflowName, other, push.sha, group)
		}
		seen[group] = push.sha

		assert.Falsef(t, evalWorkflowCondition(t, workflow.Concurrency.CancelInProgress, push),
			"%s cancels in-progress runs on push to the default branch (cancel-in-progress: %q); a later "+
				"merge would kill an earlier merge's run and leave it with no verdict",
			prScannerWorkflowName, workflow.Concurrency.CancelInProgress)
	}

	pr := pullRequest(1, "a1a1a1a", "1001")
	group := evalWorkflowTemplate(t, workflow.Concurrency.Group, pr)
	assert.NotContainsf(t, seen, group,
		"%s puts pull request #%d and a push to the default branch into the same concurrency group %q",
		prScannerWorkflowName, pr.number, group)
}

// TestPRScannerStillSupersedesPullRequestRuns keeps the fix above from
// overshooting. Pushing to a PR branch should still cancel that PR's previous
// run - that is what the concurrency block was for before master was built at
// all - so runs for one PR must share a group and cancel, while runs for two
// PRs must not. The two PRs come from forks whose branches are both named
// patch-1, as GitHub names them by default, so a group keyed on head_ref
// instead of the PR's own ref would make one PR cancel the other's run.
func TestPRScannerStillSupersedesPullRequestRuns(t *testing.T) {
	workflow := loadPRScanner(t)

	first := pullRequest(1, "a1a1a1a", "1001")
	update := pullRequest(1, "b2b2b2b", "1002")
	other := pullRequest(2, "c3c3c3c", "1003")

	firstGroup := evalWorkflowTemplate(t, workflow.Concurrency.Group, first)
	assert.Equalf(t, firstGroup, evalWorkflowTemplate(t, workflow.Concurrency.Group, update),
		"%s puts two runs of the same pull request into different concurrency groups, so a push to the PR no "+
			"longer supersedes the run it made obsolete; group PR runs by github.ref", prScannerWorkflowName)
	assert.NotEqualf(t, firstGroup, evalWorkflowTemplate(t, workflow.Concurrency.Group, other),
		"%s puts pull requests #%d and #%d into the same concurrency group %q, so one PR's run cancels or "+
			"replaces the other's; group PR runs by github.ref", prScannerWorkflowName, first.number, other.number,
		firstGroup)

	assert.Truef(t, evalWorkflowCondition(t, workflow.Concurrency.CancelInProgress, update),
		"%s no longer cancels a superseded pull request run (cancel-in-progress: %q)",
		prScannerWorkflowName, workflow.Concurrency.CancelInProgress)
}

// concurrencyEvent is the slice of the github context the concurrency block may
// reasonably read. Anything else is rejected by evalWorkflowTemplate, so an
// expression change that reaches for a new property has to be modelled here.
type concurrencyEvent struct {
	eventName string
	ref       string
	headRef   string
	sha       string
	runID     string
	number    int
}

func pullRequest(number int, sha, runID string) concurrencyEvent {
	return concurrencyEvent{
		eventName: "pull_request",
		ref:       fmt.Sprintf("refs/pull/%d/merge", number),
		headRef:   "patch-1",
		sha:       sha,
		runID:     runID,
		number:    number,
	}
}

func masterPush(sha, runID string) concurrencyEvent {
	return concurrencyEvent{
		eventName: "push",
		ref:       "refs/heads/master",
		sha:       sha,
		runID:     runID,
	}
}

func (e concurrencyEvent) context() map[string]string {
	return map[string]string{
		"github.workflow":   "00-pr_scanner",
		"github.event_name": e.eventName,
		"github.ref":        e.ref,
		"github.head_ref":   e.headRef,
		"github.sha":        e.sha,
		"github.run_id":     e.runID,
	}
}

// evalWorkflowCondition evaluates a boolean workflow field such as
// cancel-in-progress. An absent field is false, as it is to GitHub.
func evalWorkflowCondition(t *testing.T, field string, event concurrencyEvent) bool {
	t.Helper()

	return evalWorkflowTemplate(t, field, event) == "true"
}

// evalWorkflowTemplate renders a workflow field the way the runner does: literal
// text is kept and each ${{ }} is replaced by its value. It understands the
// subset of the expression language concurrency blocks are written in - context
// properties, string literals, true/false/null, parentheses, ==, !=, !, && and
// || with GitHub's value-returning semantics - and fails the test on anything
// else rather than guessing.
func evalWorkflowTemplate(t *testing.T, field string, event concurrencyEvent) string {
	t.Helper()

	var out strings.Builder
	rest := field
	for {
		open := strings.Index(rest, "${{")
		if open < 0 {
			out.WriteString(rest)
			return strings.TrimSpace(out.String())
		}
		end := strings.Index(rest[open:], "}}")
		require.GreaterOrEqualf(t, end, 0, "unterminated expression in %q", field)

		out.WriteString(rest[:open])
		parser := exprParser{t: t, source: field, tokens: tokenizeExpr(t, rest[open+3:open+end]), context: event.context()}
		value := parser.or()
		require.Equalf(t, len(parser.tokens), parser.pos, "unexpected trailing tokens in %q", field)
		out.WriteString(exprString(value))
		rest = rest[open+end+2:]
	}
}

func tokenizeExpr(t *testing.T, expr string) []string {
	t.Helper()

	var tokens []string
	for i := 0; i < len(expr); {
		switch c := expr[i]; {
		case c == ' ' || c == '\t' || c == '\n':
			i++
		case c == '(' || c == ')':
			tokens = append(tokens, string(c))
			i++
		case strings.HasPrefix(expr[i:], "&&"), strings.HasPrefix(expr[i:], "||"),
			strings.HasPrefix(expr[i:], "=="), strings.HasPrefix(expr[i:], "!="):
			tokens = append(tokens, expr[i:i+2])
			i += 2
		case c == '!':
			tokens = append(tokens, "!")
			i++
		case c == '\'':
			// '' is an escaped quote inside a string literal.
			j := i + 1
			for ; j < len(expr); j++ {
				if expr[j] == '\'' {
					if j+1 < len(expr) && expr[j+1] == '\'' {
						j++
						continue
					}
					break
				}
			}
			require.Lessf(t, j, len(expr), "unterminated string literal in %q", expr)
			tokens = append(tokens, expr[i:j+1])
			i = j + 1
		case unicode.IsLetter(rune(c)) || c == '_':
			j := i
			for j < len(expr) && (unicode.IsLetter(rune(expr[j])) || unicode.IsDigit(rune(expr[j])) ||
				expr[j] == '_' || expr[j] == '.' || expr[j] == '-') {
				j++
			}
			tokens = append(tokens, expr[i:j])
			i = j
		default:
			require.Failf(t, "unsupported expression", "cannot evaluate %q at %q; extend evalWorkflowTemplate",
				expr, expr[i:])
		}
	}
	return tokens
}

// exprParser evaluates while it parses. Values are string, bool or nil.
type exprParser struct {
	t       *testing.T
	source  string
	tokens  []string
	pos     int
	context map[string]string
}

func (p *exprParser) peek() string {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return ""
}

func (p *exprParser) or() any {
	left := p.and()
	for p.peek() == "||" {
		p.pos++
		right := p.and()
		if !exprTruthy(left) {
			left = right
		}
	}
	return left
}

func (p *exprParser) and() any {
	left := p.unary()
	for p.peek() == "&&" {
		p.pos++
		right := p.unary()
		if exprTruthy(left) {
			left = right
		}
	}
	return left
}

func (p *exprParser) unary() any {
	if p.peek() == "!" {
		p.pos++
		return !exprTruthy(p.unary())
	}
	return p.comparison()
}

func (p *exprParser) comparison() any {
	left := p.primary()
	switch op := p.peek(); op {
	case "==", "!=":
		p.pos++
		// String comparison in workflow expressions ignores case.
		equal := strings.EqualFold(exprString(left), exprString(p.primary()))
		return equal == (op == "==")
	}
	return left
}

func (p *exprParser) primary() any {
	p.t.Helper()

	token := p.peek()
	require.NotEmptyf(p.t, token, "expression in %q ends early", p.source)
	p.pos++

	switch {
	case token == "(":
		value := p.or()
		require.Equalf(p.t, ")", p.peek(), "unbalanced parentheses in %q", p.source)
		p.pos++
		return value
	case strings.HasPrefix(token, "'"):
		return strings.ReplaceAll(token[1:len(token)-1], "''", "'")
	case token == "true", token == "false":
		return token == "true"
	case token == "null":
		return nil
	}

	value, ok := p.context[token]
	require.Truef(p.t, ok, "%q in %q is not modelled by concurrencyEvent; add it there", token, p.source)
	return value
}

func exprTruthy(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return v != ""
	default:
		return false
	}
}

func exprString(value any) string {
	switch v := value.(type) {
	case bool:
		if v {
			return "true"
		}
		return "false"
	case string:
		return v
	default:
		return ""
	}
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
