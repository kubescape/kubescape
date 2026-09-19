// This test guards how 02-release.yaml materialises the cosign signing key.
//
// The release job wrote it with `echo "${{ secrets.COSIGN_PRIVATE_KEY_V1 }}" >
// cosign.key` and never removed it. Two things follow from that line. The
// redirection creates the file under the runner's default umask, so private
// key material landed at mode 0644; and `${{ }}` is substituted before the
// shell starts, so the key was part of the command the step ran rather than an
// input to it. With no cleanup step the file then stayed in the workspace for
// the rest of the job - past the E2E hook, the system tests, and the
// third-party actions that run after goreleaser.
//
// Nothing failed. The key is password-encrypted and goreleaser signed the
// images exactly as intended, so a release looked identical either way; the
// only difference was how much of the job the key was readable for.
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
	// releaseJobName is the job that builds, signs and publishes a release.
	releaseJobName = "release"

	// cosignKeyFile is the path goreleaser's docker_signs block reads the
	// signing key from. It is written by 02-release.yaml and consumed by the
	// GoReleaser step; nothing else in the repository touches it.
	cosignKeyFile = "cosign.key"

	// cosignKeySecret is the secret holding the key. An `env:` entry has to
	// carry it, because the alternative is interpolating it into the script.
	cosignKeySecret = "COSIGN_PRIVATE_KEY_V1"

	// secretsExpression is the prefix of any `${{ secrets.* }}` reference.
	// Matching on this rather than on cosignKeySecret keeps the assertion
	// honest if the environment variable is ever named after the secret.
	secretsExpression = "secrets."
)

// cosignKeyStep is the subset of a workflow step these tests assert on.
// releaseWorkflow decodes the same file for a different question and reads only
// `name`/`uses`, so the step body is decoded here instead of widening that one.
type cosignKeyStep struct {
	Name string            `yaml:"name"`
	If   string            `yaml:"if"`
	Run  string            `yaml:"run"`
	Env  map[string]string `yaml:"env"`
}

type cosignKeyWorkflow struct {
	Jobs map[string]struct {
		Steps []cosignKeyStep `yaml:"steps"`
	} `yaml:"jobs"`
}

// releaseSteps returns the steps of the release job, failing with a message
// that says what to do if the job is ever renamed.
func releaseSteps(t *testing.T) []cosignKeyStep {
	t.Helper()

	var workflow cosignKeyWorkflow
	loadWorkflow(t, releaseWorkflowName, &workflow)

	job, ok := workflow.Jobs[releaseJobName]
	require.Truef(t, ok, "%s has no %q job; this guard needs updating to follow it",
		releaseWorkflowName, releaseJobName)
	require.NotEmptyf(t, job.Steps, "%s's %q job declares no steps",
		releaseWorkflowName, releaseJobName)

	return job.Steps
}

// TestCosignKeyIsWrittenWithRestrictedPermissions is the direct regression
// test. It asserts on the step that creates the key rather than on a step name,
// so renaming the step does not silently drop the guard.
func TestCosignKeyIsWrittenWithRestrictedPermissions(t *testing.T) {
	var writers []string
	for _, step := range releaseSteps(t) {
		// The writer is whichever step redirects into the key file. A step that
		// only removes it is not one, hence the redirection rather than a bare
		// mention of the filename.
		if !strings.Contains(step.Run, "> "+cosignKeyFile) {
			continue
		}
		writers = append(writers, step.Name)

		// `${{ secrets.* }}` is expanded into the script before the shell runs,
		// which puts the key on the step's command line. An `env:` entry is
		// passed to the process instead.
		assert.NotContainsf(t, step.Run, secretsExpression,
			"%s's %q step interpolates a ${{ %s* }} value into its `run:` script; pass it through `env:` "+
				"and reference the variable, so the key is never part of the command itself",
			releaseWorkflowName, step.Name, secretsExpression)

		var fromEnv bool
		for _, value := range step.Env {
			if strings.Contains(value, cosignKeySecret) {
				fromEnv = true
				break
			}
		}
		assert.Truef(t, fromEnv,
			"%s's %q step writes %s but no `env:` entry carries secrets.%s; the key has to reach the "+
				"script as an environment variable",
			releaseWorkflowName, step.Name, cosignKeyFile, cosignKeySecret)

		// A redirection creates the file under the runner's default umask -
		// 0644 on GitHub-hosted runners. Either tightening the umask before
		// creating it or fixing the mode explicitly closes that; both forms are
		// accepted so a later rewrite is not forced into one of them.
		restricted := strings.Contains(step.Run, "umask 077") ||
			strings.Contains(step.Run, "chmod 600 "+cosignKeyFile) ||
			strings.Contains(step.Run, "install -m 600")
		assert.Truef(t, restricted,
			"%s's %q step writes %s without restricting its permissions; a plain redirection uses the "+
				"runner's default umask, so the signing key lands world-readable in a workspace shared "+
				"with every later step in the job",
			releaseWorkflowName, step.Name, cosignKeyFile)
	}

	require.Lenf(t, writers, 1,
		"expected exactly one step in %s to write %s, found %v; this guard asserts on the step that "+
			"creates the key and cannot tell which one to check",
		releaseWorkflowName, cosignKeyFile, writers)
}

// TestCosignKeyIsRemovedAfterTheRelease covers the other half. The key only has
// to exist while goreleaser runs, and `if: always()` is what makes that true of
// a failed release too - which is the run most likely to leave the workspace
// behind for inspection.
func TestCosignKeyIsRemovedAfterTheRelease(t *testing.T) {
	steps := releaseSteps(t)

	var removed, unconditional bool
	for _, step := range steps {
		if !strings.Contains(step.Run, "rm -f "+cosignKeyFile) {
			continue
		}
		// The step that creates the key also clears a stale copy first; that
		// one is not the cleanup.
		if strings.Contains(step.Run, "> "+cosignKeyFile) {
			continue
		}
		removed = true
		if strings.Contains(step.If, "always()") {
			unconditional = true
		}
	}

	require.Truef(t, removed,
		"no step in %s removes %s; the signing key stays in the workspace for the rest of the job, "+
			"which continues past goreleaser into the system tests and the third-party actions after them",
		releaseWorkflowName, cosignKeyFile)
	assert.Truef(t, unconditional,
		"%s removes %s only on success; a release that fails after the key is written leaves it behind, "+
			"so the cleanup needs `if: always()`",
		releaseWorkflowName, cosignKeyFile)
}
