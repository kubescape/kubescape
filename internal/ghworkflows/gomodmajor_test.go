package ghworkflows

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

// These tests guard the major-version suffix on this repository's module
// paths, the one piece of release metadata Go's toolchain enforces and no
// human reliably notices.
//
// Go's Semantic Import Versioning makes the suffix part of the module's
// identity: a module declaring `.../v3` can only ever be published under v3
// tags. The repository moved to v4 tags at v4.0.0 and left both go.mod files
// declaring `/v3`, so every release from v4.0.0 to v4.0.12 was unresolvable as
// a Go module - `go install .../v4@latest` and `go get` alike failed, and
// downstream importers stayed pinned to v3.0.48 for the whole v4 line.
//
// Nothing caught it because tagging a release touches no file: the drift is
// created by a `git push --tags`, not by a diff a reviewer reads. These tests
// turn the tags themselves into the assertion, and 02-release.yaml runs the
// same check before it publishes anything.
const (
	rootModuleFile        = "go.mod"
	httphandlerModuleFile = "httphandler/go.mod"
)

// releaseTagRe matches the release tags this project actually publishes. It is
// deliberately the same shape as the `on.push.tags` filter in 02-release.yaml
// ("v[0-9]+.[0-9]+.[0-9]+"), so "a release" means the same thing to this test
// as it does to the workflow that creates one. Pre-release tags (v3.0.46-rc.0)
// are excluded: they are not what consumers resolve.
var releaseTagRe = regexp.MustCompile(`^v(\d+)\.\d+\.\d+$`)

// parseModule reads and parses one of the repository's go.mod files.
func parseModule(t *testing.T, relPath string) *modfile.File {
	t.Helper()

	path := filepath.Join(repoRoot(t), filepath.FromSlash(relPath))
	content, err := os.ReadFile(path)
	require.NoErrorf(t, err, "cannot read %s", relPath)

	parsed, err := modfile.Parse(relPath, content, nil)
	require.NoErrorf(t, err, "%s is not a parseable go.mod", relPath)
	require.NotNilf(t, parsed.Module, "%s declares no module path", relPath)

	return parsed
}

// majorSuffix returns the numeric major version encoded in a module path's
// suffix. An unsuffixed path is v1 by definition, which is the one case Go
// spells with no suffix at all.
func majorSuffix(t *testing.T, modulePath string) int {
	t.Helper()

	_, pathMajor, ok := module.SplitPathVersion(modulePath)
	require.Truef(t, ok, "%q is not a valid module path", modulePath)

	if pathMajor == "" {
		return 1
	}

	// pathMajor is "/vN" for the suffixed form.
	major, err := strconv.Atoi(pathMajor[len("/v"):])
	require.NoErrorf(t, err, "cannot read a major version out of suffix %q", pathMajor)

	return major
}

// rootModulePath is the declared module path of the repository root, the
// single value every other assertion in this file is measured against.
func rootModulePath(t *testing.T) string {
	t.Helper()

	return parseModule(t, rootModuleFile).Module.Mod.Path
}

// latestReleaseMajor reports the highest major version among the repository's
// release tags.
//
// It skips rather than fails when the tags are not there: `actions/checkout`
// fetches no tags unless asked, and a contributor's shallow clone has none
// either. The workflows that must enforce this - a-pr-scanner.yaml and
// 02-release.yaml - both check out with fetch-depth: 0, which fetches tags,
// and TestReleaseWorkflowChecksModuleMajor keeps the release-time guard
// wired up so the skip cannot quietly become the normal case.
func latestReleaseMajor(t *testing.T) (int, bool) {
	t.Helper()

	git, err := exec.LookPath("git")
	if err != nil {
		t.Log("git is not on PATH; skipping the release-tag comparison")
		return 0, false
	}

	cmd := exec.Command(git, "tag", "--list", "v*")
	cmd.Dir = repoRoot(t)
	out, err := cmd.Output()
	if err != nil {
		t.Logf("cannot list git tags (%v); skipping the release-tag comparison", err)
		return 0, false
	}

	highest, found := 0, false
	for _, tag := range regexp.MustCompile(`\r?\n`).Split(string(out), -1) {
		match := releaseTagRe.FindStringSubmatch(tag)
		if match == nil {
			continue
		}

		major, err := strconv.Atoi(match[1])
		require.NoErrorf(t, err, "cannot read a major version out of tag %q", tag)

		if major > highest {
			highest, found = major, true
		}
	}

	return highest, found
}

// TestGoModMajorMatchesReleaseTags is the direct regression test for the
// v4-tagged-but-v3-declared breakage: it fails for exactly the state the
// repository shipped in for thirteen releases.
func TestGoModMajorMatchesReleaseTags(t *testing.T) {
	releaseMajor, found := latestReleaseMajor(t)
	if !found {
		t.Skip("no release tags in this checkout; nothing to compare the module path against")
	}

	modulePath := rootModulePath(t)

	assert.Equalf(t, releaseMajor, majorSuffix(t, modulePath),
		"%s declares module %q but the newest release tag is v%d.x; "+
			"Go resolves a module by the major version in its path, so every v%d tag is uninstallable "+
			"until the module path ends in /v%d (and every internal import follows it)",
		rootModuleFile, modulePath, releaseMajor, releaseMajor, releaseMajor)
}

// TestHTTPHandlerModuleTracksRoot keeps the submodule from drifting away from
// the module it is nested in. httphandler/go.mod names the root module three
// times - its own path, the require, and the local replace - and a local
// `replace ... => ../` makes a stale major invisible: the submodule keeps
// building in-tree while being unresolvable to anyone outside the repository,
// which is precisely how its `/v3` suffix survived the v4 release line.
func TestHTTPHandlerModuleTracksRoot(t *testing.T) {
	root := rootModulePath(t)
	submodule := parseModule(t, httphandlerModuleFile)

	assert.Equalf(t, root+"/httphandler", submodule.Module.Mod.Path,
		"%s must be the root module path plus /httphandler", httphandlerModuleFile)

	rootMajor := majorSuffix(t, root)

	var required bool
	for _, req := range submodule.Require {
		if _, _, ok := module.SplitPathVersion(req.Mod.Path); !ok || req.Mod.Path != root {
			continue
		}
		required = true

		assert.Equalf(t, rootMajor, majorSuffix(t, req.Mod.Path),
			"%s requires %q, which is not the root module's major version",
			httphandlerModuleFile, req.Mod.Path)
	}
	assert.Truef(t, required,
		"%s must require %q; it imports the root module's packages",
		httphandlerModuleFile, root)

	var replaced bool
	for _, rep := range submodule.Replace {
		if rep.New.Path != "../" && rep.New.Path != ".." {
			continue
		}
		replaced = true

		assert.Equalf(t, root, rep.Old.Path,
			"%s replaces %q with the parent directory, but the parent declares %q; "+
				"a replace that names a stale module path silently stops applying",
			httphandlerModuleFile, rep.Old.Path, root)
	}
	assert.Truef(t, replaced,
		"%s must replace %q with ../ so the submodule builds against the working tree",
		httphandlerModuleFile, root)
}

// TestReleaseWorkflowChecksModuleMajor keeps the release-time guard in place.
//
// The pull-request checks can only ever see a tag that already exists, and the
// drift this package exists to prevent is created by pushing a tag, so the
// assertion that actually matters runs in 02-release.yaml against the tag being
// released. Without it, the test above degrades into a report of damage already
// shipped; this keeps it a gate.
func TestReleaseWorkflowChecksModuleMajor(t *testing.T) {
	content, err := os.ReadFile(filepath.Join(workflowsDir(t), releaseWorkflow))
	require.NoErrorf(t, err, "cannot read %s", releaseWorkflow)

	assert.Containsf(t, string(content), moduleMajorGuardStep,
		"%s must keep the %q step: it is the only check that runs before a release is published, "+
			"and it is what stops a vN tag from shipping against a v(N-1) module path",
		releaseWorkflow, moduleMajorGuardStep)
}

const (
	// releaseWorkflow publishes a release when a vN.N.N tag is pushed.
	releaseWorkflow = "02-release.yaml"

	// moduleMajorGuardStep is the name of the step in releaseWorkflow that
	// rejects a tag whose major version the module path does not carry.
	moduleMajorGuardStep = "Verify module path matches release tag"
)
