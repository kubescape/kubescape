// This test guards the vulnerability check on kubescape's own dependencies.
//
// Kubescape exists to find vulnerable components in other people's software,
// and until this check CI ran nothing of the kind on its own module graph:
// dependabot proposes version bumps, but nothing reported that a released
// binary reaches a known-vulnerable function. v4.0.15 shipped reaching seven,
// three of them with a fixed release already available.
//
// The check runs govulncheck through .github/scripts/govulncheck.sh. Two
// properties of it are easy to break without anything noticing, so they are
// asserted here:
//
//   - The toolchain. govulncheck reports standard-library vulnerabilities
//     against the Go it runs on. The unit-test job uses go.mod's minimum
//     version, which lags the release build, so running the check there would
//     report standard-library issues that no released binary contains and
//     bury the dependency findings that matter. The job must use the release
//     workflow's Go line.
//   - The pin. A govulncheck release can change output format or exit codes,
//     and the script depends on both, so the version is fixed and bumped
//     deliberately.
//
// Deliberately test-only: this is a repository-hygiene guard, so it adds no
// production surface.
package ghworkflows

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// prScannerReusableWorkflowName holds the jobs 00-pr-scanner.yaml runs.
	prScannerReusableWorkflowName = "a-pr-scanner.yaml"

	// govulncheckScript is the script the vulnerability job runs, relative to
	// the repository root.
	govulncheckScript = ".github/scripts/govulncheck.sh"

	setupGoAction = "actions/setup-go@"
)

// stepsWorkflow is the subset of a workflow these tests assert on: each job's
// gate and steps. `with` and continue-on-error values are decoded as strings;
// yaml.v3 accepts any scalar there.
type stepsWorkflow struct {
	Jobs map[string]struct {
		If              string `yaml:"if"`
		ContinueOnError string `yaml:"continue-on-error"`
		Steps           []struct {
			Uses            string            `yaml:"uses"`
			Run             string            `yaml:"run"`
			With            map[string]string `yaml:"with"`
			ContinueOnError string            `yaml:"continue-on-error"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// setupGoVersions returns the `go-version` and `go-version-file` inputs of
// every actions/setup-go step in one job.
func setupGoVersions(workflow stepsWorkflow, job string) (versions, versionFiles []string) {
	for _, step := range workflow.Jobs[job].Steps {
		if !strings.HasPrefix(step.Uses, setupGoAction) {
			continue
		}
		if v, ok := step.With["go-version"]; ok {
			versions = append(versions, v)
		}
		if f, ok := step.With["go-version-file"]; ok {
			versionFiles = append(versionFiles, f)
		}
	}
	return versions, versionFiles
}

// govulncheckJob returns the name of the a-pr-scanner.yaml job that runs the
// script, failing the test when there is none.
func govulncheckJob(t *testing.T, workflow stepsWorkflow) string {
	t.Helper()

	var jobs []string
	for name, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if strings.Contains(step.Run, govulncheckScript) {
				jobs = append(jobs, name)
				break
			}
		}
	}
	require.Lenf(t, jobs, 1,
		"%s must run %s in exactly one job; without it CI reports nothing about vulnerable code kubescape ships",
		prScannerReusableWorkflowName, govulncheckScript)
	return jobs[0]
}

// TestPRScannerRunsGovulncheck is the direct regression test: the PR scanner
// runs the vulnerability check, and the script it runs exists.
func TestPRScannerRunsGovulncheck(t *testing.T) {
	var workflow stepsWorkflow
	loadWorkflow(t, prScannerReusableWorkflowName, &workflow)

	govulncheckJob(t, workflow)

	info, err := os.Stat(filepath.Join(repoRoot(t), filepath.FromSlash(govulncheckScript)))
	require.NoErrorf(t, err, "%s runs %s, which does not exist", prScannerReusableWorkflowName, govulncheckScript)
	assert.False(t, info.IsDir())
}

// TestGovulncheckUsesReleaseGoVersion asserts the check runs on the Go line the
// release is built with, so its standard-library findings describe what ships.
func TestGovulncheckUsesReleaseGoVersion(t *testing.T) {
	var release stepsWorkflow
	loadWorkflow(t, releaseWorkflowName, &release)

	releaseVersions := map[string]bool{}
	for job := range release.Jobs {
		versions, _ := setupGoVersions(release, job)
		for _, v := range versions {
			releaseVersions[v] = true
		}
	}
	require.Lenf(t, releaseVersions, 1,
		"%s should build with a single go-version; found %v, so there is no one toolchain to check against",
		releaseWorkflowName, releaseVersions)

	var scanner stepsWorkflow
	loadWorkflow(t, prScannerReusableWorkflowName, &scanner)
	job := govulncheckJob(t, scanner)

	versions, versionFiles := setupGoVersions(scanner, job)
	assert.Emptyf(t, versionFiles,
		"%s job %q sets go-version-file; go.mod's go line is a minimum and lags the release toolchain, so "+
			"standard-library findings would describe a Go version that is never shipped", prScannerReusableWorkflowName, job)
	require.Lenf(t, versions, 1, "%s job %q must install Go with exactly one setup-go go-version", prScannerReusableWorkflowName, job)
	assert.Truef(t, releaseVersions[versions[0]],
		"%s job %q installs Go %q but %s builds with %v; keep them in step",
		prScannerReusableWorkflowName, job, versions[0], releaseWorkflowName, releaseVersions)
}

// TestGovulncheckVersionIsPinned asserts the script installs an exact
// govulncheck release rather than whatever is newest.
func TestGovulncheckVersionIsPinned(t *testing.T) {
	content, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(govulncheckScript)))
	require.NoError(t, err)
	script := string(content)

	assert.Regexp(t, regexp.MustCompile(`(?m)^GOVULNCHECK_VERSION="v\d+\.\d+\.\d+"$`), script,
		"%s must pin govulncheck to an exact vX.Y.Z release", govulncheckScript)
	assert.NotContains(t, script, "govulncheck@latest",
		"%s must not install govulncheck@latest; its exit codes and output format are part of this check's contract",
		govulncheckScript)
	assert.NotRegexp(t, regexp.MustCompile(`(?m)^[^#\n]*\bgo run\b`), script,
		"%s must run the installed govulncheck binary; go run turns its exit code 3 (found) into 1", govulncheckScript)
}

// TestGovulncheckRunsOnPushToMaster asserts the job is reached on a merge to
// master as well as on a PR. The master push trigger lives on
// 00-pr-scanner.yaml (guarded in masterbuild_test.go), which reaches this job
// only by calling a-pr-scanner.yaml, and the job must not be gated differently
// from the build it runs beside.
func TestGovulncheckRunsOnPushToMaster(t *testing.T) {
	var caller struct {
		On struct {
			Push struct {
				Branches []string `yaml:"branches"`
			} `yaml:"push"`
		} `yaml:"on"`
		Jobs map[string]struct {
			Uses string `yaml:"uses"`
		} `yaml:"jobs"`
	}
	loadWorkflow(t, prScannerWorkflowName, &caller)
	require.Containsf(t, caller.On.Push.Branches, "master", "%s must run on pushes to master", prScannerWorkflowName)

	calls := false
	for _, job := range caller.Jobs {
		if job.Uses == "./.github/workflows/"+prScannerReusableWorkflowName {
			calls = true
		}
	}
	require.Truef(t, calls, "%s must call %s, which holds the govulncheck job",
		prScannerWorkflowName, prScannerReusableWorkflowName)

	var scanner stepsWorkflow
	loadWorkflow(t, prScannerReusableWorkflowName, &scanner)
	job := govulncheckJob(t, scanner)
	build, ok := scanner.Jobs["unit-tests"]
	require.Truef(t, ok, "%s has no unit-tests job to compare the govulncheck job's gate with", prScannerReusableWorkflowName)
	assert.Equalf(t, build.If, scanner.Jobs[job].If,
		"%s job %q must be gated like the build job, so it runs on every event the build runs on",
		prScannerReusableWorkflowName, job)
}

// TestGovulncheckFailuresAreNotHidden asserts nothing in the job turns a failed
// scan into a green check.
func TestGovulncheckFailuresAreNotHidden(t *testing.T) {
	var scanner stepsWorkflow
	loadWorkflow(t, prScannerReusableWorkflowName, &scanner)
	name := govulncheckJob(t, scanner)
	job := scanner.Jobs[name]

	assert.Containsf(t, []string{"", "false"}, job.ContinueOnError,
		"%s job %q must not set continue-on-error; a scan that cannot complete has to fail the check",
		prScannerReusableWorkflowName, name)
	for _, step := range job.Steps {
		assert.Containsf(t, []string{"", "false"}, step.ContinueOnError,
			"%s job %q step %q must not set continue-on-error", prScannerReusableWorkflowName, name, step.Uses+step.Run)
	}
}

// TestMakeVulncheckRunsTheScript asserts `make vulncheck` runs the same check
// CI runs, so a local run reports what CI reports.
func TestMakeVulncheckRunsTheScript(t *testing.T) {
	content, err := os.ReadFile(filepath.Join(repoRoot(t), "Makefile"))
	require.NoError(t, err)
	makefile := string(content)

	recipe := regexp.MustCompile(`(?m)^vulncheck:[^\n]*\n((?:\t[^\n]*\n)+)`).FindStringSubmatch(makefile)
	require.NotNil(t, recipe, "Makefile must define a vulncheck target")
	assert.Equal(t, "\tbash "+govulncheckScript+"\n", recipe[1],
		"make vulncheck must run %s and nothing else, so it matches CI", govulncheckScript)
	assert.Regexp(t, regexp.MustCompile(`(?m)^\.PHONY:.*\bvulncheck\b`), makefile, "vulncheck is not a file; list it in .PHONY")
}

// govulncheckFindings is a govulncheck v1.8.0 text report, trimmed to three
// findings that cover each shape the script parses: a module with a fixed
// release, a module with none ("Fixed in: N/A") and the standard library.
const govulncheckFindings = `=== Symbol Results ===

Vulnerability #1: GO-2026-6615
    OpenTelemetry-Go: BatchProcessor can busy-spin when export buffer is full in
    go.opentelemetry.io/otel/sdk/log
  More info: https://pkg.go.dev/vuln/GO-2026-6615
  Module: go.opentelemetry.io/otel/sdk/log
    Found in: go.opentelemetry.io/otel/sdk/log@v0.19.0
    Fixed in: go.opentelemetry.io/otel/sdk/log@v0.21.0
    Example traces found:
      #1: httphandler/main.go:81:18: httphandler.run calls logger.InitOtel, which eventually calls log.NewBatchProcessor

Vulnerability #2: GO-2026-6596
    Cilium: Namespaced HTTPRoutes can redirect traffic to other namespaces in
    github.com/cilium/cilium
  More info: https://pkg.go.dev/vuln/GO-2026-6596
  Module: github.com/cilium/cilium
    Found in: github.com/cilium/cilium@v1.19.4
    Fixed in: N/A
    Example traces found:
      #1: core/pkg/containerscan/elasticadapters.go:5:2: containerscan.init calls armometadata.init, which eventually calls cache.Cache[string].Get[string]

Vulnerability #3: GO-2026-6218
    Avoid quadratic complexity in resolvePath in net/url
  More info: https://pkg.go.dev/vuln/GO-2026-6218
  Standard library
    Found in: net/url@go1.26.5
    Fixed in: net/url@go1.26.6
    Example traces found:
      #1: core/cautils/helmchart.go:129:21: cautils.buildDependencies calls downloader.Manager.Build, which eventually calls url.URL.ResolveReference

Your code is affected by 3 vulnerabilities from 2 modules and the Go standard library.
`

// fakeGo stands in for the go command. It accepts only the pinned install the
// script must make, and installs a govulncheck that prints $FAKE_REPORT and
// exits with $FAKE_RC, so the script's handling of every outcome can be checked
// without the network or the vulnerability database.
const fakeGo = `#!/usr/bin/env bash
if [ "$*" != "install golang.org/x/vuln/cmd/govulncheck@$FAKE_WANT_VERSION" ]; then
    echo "fake go: unexpected arguments: $*" >&2
    exit 97
fi
if [ "${FAKE_INSTALL_FAILS:-}" = "true" ]; then
    echo "fake go: download failed" >&2
    exit 1
fi
printf '%s\n' '#!/usr/bin/env bash' 'echo "$*" >"$FAKE_ARGS"' 'cat "$FAKE_REPORT"' 'exit "$FAKE_RC"' >"$GOBIN/govulncheck"
chmod +x "$GOBIN/govulncheck"
`

// TestGovulncheckScriptOutcomes runs the real script against a fake toolchain
// and checks each outcome: report mode never fails on findings, enforcing mode
// fails with govulncheck's own status, and a scan that cannot complete always
// fails.
func TestGovulncheckScriptOutcomes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the script runs on Linux runners; it needs bash")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not found")
	}

	content, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(govulncheckScript)))
	require.NoError(t, err)
	version := regexp.MustCompile(`(?m)^GOVULNCHECK_VERSION="(v[^"]+)"$`).FindStringSubmatch(string(content))
	require.NotNil(t, version)

	findings := []string{
		"::warning title=govulncheck GO-2026-6615::OpenTelemetry-Go: BatchProcessor can busy-spin when export buffer is full in go.opentelemetry.io/otel/sdk/log (fixed in: go.opentelemetry.io/otel/sdk/log@v0.21.0) https://pkg.go.dev/vuln/GO-2026-6615",
		"::warning title=govulncheck GO-2026-6596::Cilium: Namespaced HTTPRoutes can redirect traffic to other namespaces in github.com/cilium/cilium (no fixed version yet) https://pkg.go.dev/vuln/GO-2026-6596",
		"::warning title=govulncheck GO-2026-6218::Avoid quadratic complexity in resolvePath in net/url (fixed in: net/url@go1.26.6) https://pkg.go.dev/vuln/GO-2026-6218",
	}

	tests := []struct {
		name         string
		report       string
		rc           string
		enforce      bool
		installFails bool
		wantExit     int
		wantWarnings []string
		wantError    string
		wantSummary  string // empty: no summary is written
	}{
		{
			name:        "clean scan passes",
			report:      "No vulnerabilities found.\n",
			rc:          "0",
			wantExit:    0,
			wantSummary: "No reachable vulnerabilities found.",
		},
		{
			name:         "findings are reported without failing by default",
			report:       govulncheckFindings,
			rc:           "3",
			wantExit:     0,
			wantWarnings: findings,
			wantSummary:  "3 reachable vulnerabilities found. They are reported, not enforced",
		},
		{
			name:         "findings fail with govulncheck's status when enforcing",
			report:       govulncheckFindings,
			rc:           "3",
			enforce:      true,
			wantExit:     3,
			wantWarnings: findings,
			wantSummary:  "3 reachable vulnerabilities found. GOVULNCHECK_FAIL_ON_FINDINGS is true",
		},
		{
			name:        "a scan that cannot complete fails even in report mode",
			report:      "govulncheck: fetching vulnerabilities: dial tcp: lookup vuln.go.dev: no such host\n",
			rc:          "1",
			wantExit:    1,
			wantError:   "failed with exit code 1",
			wantSummary: "The scan did not complete (exit code 1).",
		},
		{
			name:        "findings that cannot be read fail instead of looking clean",
			report:      "some future report format\n",
			rc:          "3",
			wantExit:    1,
			wantError:   "none could be read from its report",
			wantSummary: "the report could not be read",
		},
		{
			name:         "an install failure fails before scanning",
			installFails: true,
			wantExit:     1,
			wantError:    "could not install govulncheck",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			require.NoError(t, os.Mkdir(bin, 0o750))
			require.NoError(t, os.WriteFile(filepath.Join(bin, "go"), []byte(fakeGo), 0o700)) //nolint:gosec // G306: the fake go must be executable
			reportFile := filepath.Join(dir, "report.txt")
			require.NoError(t, os.WriteFile(reportFile, []byte(tt.report), 0o600))
			summaryFile := filepath.Join(dir, "summary.md")
			argsFile := filepath.Join(dir, "args.txt")

			enforce, installFails := "false", "false"
			if tt.enforce {
				enforce = "true"
			}
			if tt.installFails {
				installFails = "true"
			}
			cmd := exec.Command(bash, filepath.Join(repoRoot(t), filepath.FromSlash(govulncheckScript))) //nolint:gosec // G204: runs the repository's own script under test
			cmd.Dir = dir
			cmd.Env = append(os.Environ(),
				"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
				"FAKE_WANT_VERSION="+version[1],
				"FAKE_REPORT="+reportFile,
				"FAKE_RC="+tt.rc,
				"FAKE_ARGS="+argsFile,
				"FAKE_INSTALL_FAILS="+installFails,
				"GOVULNCHECK_FAIL_ON_FINDINGS="+enforce,
				"GITHUB_STEP_SUMMARY="+summaryFile,
			)
			out, err := cmd.CombinedOutput()
			output := string(out)

			exitCode := 0
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				exitCode = exitErr.ExitCode()
			} else {
				require.NoError(t, err)
			}
			assert.Equalf(t, tt.wantExit, exitCode, "exit code; output:\n%s", output)

			var warnings []string
			for _, line := range strings.Split(output, "\n") {
				if strings.HasPrefix(line, "::warning ") {
					warnings = append(warnings, line)
				}
			}
			assert.Equal(t, tt.wantWarnings, warnings, "one warning per reachable vulnerability")
			if tt.wantError != "" {
				assert.Contains(t, output, "::error title=govulncheck::")
				assert.Contains(t, output, tt.wantError)
			} else {
				assert.NotContains(t, output, "::error")
			}

			args, err := os.ReadFile(argsFile)
			if tt.installFails {
				assert.Truef(t, os.IsNotExist(err), "govulncheck must not run after a failed install")
			} else {
				require.NoError(t, err, "the installed govulncheck was never run")
				assert.Equal(t, "./...\n", string(args), "govulncheck must scan the whole module")
			}

			summary, err := os.ReadFile(summaryFile)
			if tt.wantSummary == "" {
				assert.True(t, os.IsNotExist(err), "no summary is expected")
				return
			}
			require.NoError(t, err, "the job summary was not written")
			assert.Contains(t, string(summary), "## govulncheck "+version[1])
			assert.Contains(t, string(summary), tt.wantSummary)
			assert.Contains(t, string(summary), strings.TrimSpace(tt.report), "the summary must carry the full report")
		})
	}
}
