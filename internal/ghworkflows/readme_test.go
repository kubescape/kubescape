// Package ghworkflows holds repository-hygiene tests that keep
// .github/workflows/README.md honest about the workflows sitting next to it.
//
// The README is the first thing a new contributor reads to learn which branch
// to target and what CI will do to their PR, but nothing linked it to the
// workflow definitions, so it silently rotted: it documented `main` as the
// default branch, a `trigger-integration-test` label that no workflow reads,
// and a caller/reusable naming convention that was stated backwards. These
// tests turn each of those claims into an assertion against the YAML.
//
// Deliberately test-only: this is a documentation guard, so it adds no
// production surface.
package ghworkflows

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/internal/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	readmeName = "README.md"

	// scorecardWorkflow is the source of truth for the repository's default
	// branch. It is the only workflow that pins a branch by name
	// (on.push.branches), so it stays checked in, machine-readable, and
	// correct without a network call.
	scorecardWorkflow = "scorecard.yml"
)

// workflowsDir resolves .github/workflows from this test's own location so the
// test does not depend on the working directory `go test` is invoked from.
func workflowsDir(t *testing.T) string {
	t.Helper()

	// internal/ghworkflows -> repository root
	repoRoot := filepath.Join(testutils.CurrentDir(), "..", "..")
	dir := filepath.Join(repoRoot, ".github", "workflows")

	info, err := os.Stat(dir)
	require.NoErrorf(t, err, "cannot locate %s", dir)
	require.True(t, info.IsDir(), "%s is not a directory", dir)

	return dir
}

// workflowFiles returns every workflow definition, keyed by file name. The
// README itself is excluded; .yaml and .yml are both in use in this directory.
func workflowFiles(t *testing.T) map[string][]byte {
	t.Helper()

	dir := workflowsDir(t)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	files := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || (!strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml")) {
			continue
		}

		content, err := os.ReadFile(filepath.Join(dir, name))
		require.NoErrorf(t, err, "failed to read %s", name)
		files[name] = content
	}

	require.NotEmpty(t, files, "no workflow files found")
	return files
}

func readme(t *testing.T) string {
	t.Helper()

	content, err := os.ReadFile(filepath.Join(workflowsDir(t), readmeName))
	require.NoError(t, err)
	return string(content)
}

// workflowTriggers is the subset of a workflow's `on:` block this test needs.
// gopkg.in/yaml.v3 follows the YAML 1.2 core schema, where only true/false are
// booleans, so the `on:` key unmarshals as the plain string "on".
type workflowTriggers struct {
	On struct {
		Push struct {
			Branches []string `yaml:"branches"`
		} `yaml:"push"`
		// WorkflowCall is present-but-null for a reusable workflow that
		// declares no inputs, so its presence is detected via the node kind
		// rather than a typed value.
		WorkflowCall yaml.Node `yaml:"workflow_call"`
	} `yaml:"on"`
}

func parseTriggers(t *testing.T, name string, content []byte) workflowTriggers {
	t.Helper()

	var triggers workflowTriggers
	require.NoErrorf(t, yaml.Unmarshal(content, &triggers), "failed to parse %s", name)
	return triggers
}

// defaultBranch reads the repository's default branch out of scorecard.yml.
func defaultBranch(t *testing.T) string {
	t.Helper()

	files := workflowFiles(t)
	content, ok := files[scorecardWorkflow]
	require.Truef(t, ok, "%s is missing; it is the source of truth for the default branch", scorecardWorkflow)

	branches := parseTriggers(t, scorecardWorkflow, content).On.Push.Branches
	require.Lenf(t, branches, 1, "%s should pin exactly one branch", scorecardWorkflow)

	return branches[0]
}

// documentedBranchRe matches the README sentence naming the branch to target.
var documentedBranchRe = regexp.MustCompile("default branch is `([^`]+)`")

// TestReadmeDocumentsTheRealDefaultBranch is the regression test for the
// README claiming `main` while every PR actually targets `master`.
func TestReadmeDocumentsTheRealDefaultBranch(t *testing.T) {
	want := defaultBranch(t)

	matches := documentedBranchRe.FindStringSubmatch(readme(t))
	require.Lenf(t, matches, 2,
		"%s must state the default branch as: default branch is `<branch>`", readmeName)

	assert.Equalf(t, want, matches[1],
		"%s documents branch %q but %s pins %q; contributors branch and target from this line",
		readmeName, matches[1], scorecardWorkflow, want)
}

// documentedLabelRe matches any PR label the README claims drives CI.
var documentedLabelRe = regexp.MustCompile("`([a-z0-9][a-z0-9-]*)` label")

// TestReadmeLabelsAreReadBySomeWorkflow is the regression test for the README
// documenting a `trigger-integration-test` label that no workflow ever reads.
func TestReadmeLabelsAreReadBySomeWorkflow(t *testing.T) {
	files := workflowFiles(t)

	for _, match := range documentedLabelRe.FindAllStringSubmatch(readme(t), -1) {
		label := match[1]

		t.Run(label, func(t *testing.T) {
			for name, content := range files {
				if strings.Contains(string(content), label) {
					t.Logf("label %q is read by %s", label, name)
					return
				}
			}
			t.Errorf("%s documents the %q label as driving CI, but no workflow references it; "+
				"either wire it up or stop documenting it", readmeName, label)
		})
	}
}

// workflowFileRe matches workflow file names mentioned in the README.
var workflowFileRe = regexp.MustCompile("`([a-z0-9][a-z0-9._-]*\\.ya?ml)`")

// TestReadmeReferencesExistingWorkflows keeps the README from pointing at
// workflow files that were renamed or deleted.
func TestReadmeReferencesExistingWorkflows(t *testing.T) {
	files := workflowFiles(t)

	for _, match := range workflowFileRe.FindAllStringSubmatch(readme(t), -1) {
		name := match[1]

		t.Run(name, func(t *testing.T) {
			_, ok := files[name]
			assert.Truef(t, ok, "%s references workflow %q, which does not exist in .github/workflows",
				readmeName, name)
		})
	}
}

// TestWorkflowPrefixConventionHolds encodes the convention the README's
// "Additional Information" section states: entrypoint workflows that call
// another workflow carry a numeric prefix, and the reusable workflows they
// call carry an alphabetic prefix. The README had this backwards. Asserting
// the convention against the YAML means a future workflow that breaks it
// fails here instead of quietly making the README wrong again.
func TestWorkflowPrefixConventionHolds(t *testing.T) {
	numericPrefix := regexp.MustCompile(`^[0-9]`)
	// Asserted positively rather than as "not numeric", so a name starting with
	// punctuation or an underscore fails too instead of passing by default.
	alphabeticPrefix := regexp.MustCompile(`^[A-Za-z]`)

	for name, content := range workflowFiles(t) {
		t.Run(name, func(t *testing.T) {
			isReusable := parseTriggers(t, name, content).On.WorkflowCall.Kind != 0
			isCaller := strings.Contains(string(content), "uses: ./.github/workflows/")

			switch {
			case isReusable:
				assert.Truef(t, alphabeticPrefix.MatchString(name),
					"%s is reusable (on.workflow_call) so it should carry an alphabetic prefix", name)
			case isCaller:
				assert.Truef(t, numericPrefix.MatchString(name),
					"%s calls another workflow so it should carry a numeric prefix", name)
			default:
				// Standalone workflows (scorecard, comments) are outside the
				// caller/reusable convention and are intentionally unconstrained.
				t.Skipf("%s is standalone: neither reusable nor a caller", name)
			}
		})
	}
}
