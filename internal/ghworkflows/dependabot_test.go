// Package ghworkflows holds repository-hygiene tests: assertions over the
// configuration files under .github that nothing else checks, and that fail
// silently when they are wrong.
//
// Deliberately test-only. These guards add no production surface.
package ghworkflows

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"testing"

	"github.com/kubescape/kubescape/v4/internal/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// These tests guard .github/dependabot.yaml, which drives the only automated
// CVE patching this repository has.
//
// A malformed config fails somewhere no contributor looks: GitHub disables
// version updates for the repository and leaves the last successful run
// standing, so the dependency graph keeps looking healthy while nothing is
// patched. Commit 7218a904 ("ci: fix indentation in dependabot.yaml") replaced
// valid 2-space indentation with invalid 3/4-space and stopped Dependabot dead
// for roughly three months across ~300 modules, Grype, OPA and client-go among
// them. Nothing failed, because nothing was checking.
//
// Syntax is only half the exposure. A config that parses but has quietly lost
// an entry - the same file was broken and repaired twice before in one day -
// fails just as silently, so TestDependabotCoversEveryGoModule asserts
// coverage against the go.mod files actually on disk rather than a hardcoded
// list. Adding a third module is then covered automatically.
//
// Deliberately test-only: this is a repository-hygiene guard, so it adds no
// production surface.
const (
	dependabotConfigName = "dependabot.yaml"

	// gomodEcosystem and actionsEcosystem are Dependabot's identifiers for the
	// two ecosystems this repository ships: the Go modules themselves, and the
	// SHA-pinned actions under .github/workflows.
	gomodEcosystem   = "gomod"
	actionsEcosystem = "github-actions"

	// dependabotSchemaVersion is the only value Dependabot accepts.
	dependabotSchemaVersion = 2
)

// dependabotUpdate is the subset of an `updates` entry these tests assert on.
// Unknown keys are tolerated on purpose: Dependabot supports many optional
// options (groups, ignore, open-pull-requests-limit), and a strict decoder
// would turn adopting one of them into a spurious failure here.
type dependabotUpdate struct {
	PackageEcosystem string `yaml:"package-ecosystem"`
	Directory        string `yaml:"directory"`
	Schedule         struct {
		Interval string `yaml:"interval"`
	} `yaml:"schedule"`
}

type dependabotConfig struct {
	Version int                `yaml:"version"`
	Updates []dependabotUpdate `yaml:"updates"`
}

// repoRoot resolves the repository root from this test's own location so the
// tests do not depend on the working directory `go test` is invoked from.
func repoRoot(t *testing.T) string {
	t.Helper()

	// internal/ghworkflows -> repository root
	return filepath.Join(testutils.CurrentDir(), "..", "..")
}

func dependabotConfigPath(t *testing.T) string {
	t.Helper()

	return filepath.Join(repoRoot(t), ".github", dependabotConfigName)
}

// loadDependabotConfig reads and parses the config, surfacing the parser's own
// message on failure. This is the assertion 7218a904 would have tripped.
func loadDependabotConfig(t *testing.T) dependabotConfig {
	t.Helper()

	configPath := dependabotConfigPath(t)
	content, err := os.ReadFile(configPath)
	require.NoErrorf(t, err, "cannot read %s", configPath)

	var config dependabotConfig
	require.NoErrorf(t, yaml.Unmarshal(content, &config),
		"%s is not valid YAML; GitHub disables version updates for a config it cannot parse, "+
			"and reports that nowhere a contributor will see it", configPath)

	return config
}

// normalizeDirectory renders a configured `directory` in the same form
// goModuleDirectories produces, so "/httphandler", "httphandler" and
// "/httphandler/" all compare equal.
func normalizeDirectory(directory string) string {
	return path.Join("/", filepath.ToSlash(directory))
}

// goModuleDirectories returns the Dependabot `directory` value for every Go
// module in the repository, discovered from the go.mod files on disk so that a
// module added later is covered without editing this test.
func goModuleDirectories(t *testing.T) []string {
	t.Helper()

	root := repoRoot(t)
	var directories []string

	err := filepath.WalkDir(root, func(currentPath string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			// Skip trees that never hold a module Dependabot should track: VCS
			// metadata, vendored copies, and fixtures that may carry their own
			// go.mod purely as test input.
			switch entry.Name() {
			case ".git", "vendor", "testdata", "node_modules":
				return fs.SkipDir
			}
			return nil
		}
		if entry.Name() != "go.mod" {
			return nil
		}

		relative, err := filepath.Rel(root, filepath.Dir(currentPath))
		if err != nil {
			return err
		}
		directories = append(directories, normalizeDirectory(relative))

		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, directories, "no go.mod found; the walk is looking in the wrong place")

	sort.Strings(directories)
	return directories
}

// TestDependabotConfigIsValid is the direct regression test for 7218a904: the
// config must parse, and must carry the fields Dependabot requires before it
// will schedule anything.
func TestDependabotConfigIsValid(t *testing.T) {
	config := loadDependabotConfig(t)

	require.Equalf(t, dependabotSchemaVersion, config.Version,
		"Dependabot only accepts version %d", dependabotSchemaVersion)
	require.NotEmpty(t, config.Updates,
		"an empty updates list disables Dependabot as completely as a parse error does")

	for i, update := range config.Updates {
		t.Run(fmt.Sprintf("updates[%d]", i), func(t *testing.T) {
			assert.NotEmpty(t, update.PackageEcosystem, "package-ecosystem is required")
			assert.NotEmpty(t, update.Directory, "directory is required")
			assert.NotEmptyf(t, update.Schedule.Interval,
				"schedule.interval is required; the %q entry would never run without it",
				update.PackageEcosystem)
		})
	}
}

// TestDependabotCoversEveryGoModule catches the silent half of this failure
// mode: a config that parses but no longer covers every module. This repository
// ships the root module, and this test asserts coverage against all go.mod files
// on disk so adding a module later is covered automatically.
func TestDependabotCoversEveryGoModule(t *testing.T) {
	config := loadDependabotConfig(t)

	tracked := make(map[string]struct{}, len(config.Updates))
	for _, update := range config.Updates {
		if update.PackageEcosystem == gomodEcosystem {
			tracked[normalizeDirectory(update.Directory)] = struct{}{}
		}
	}

	for _, directory := range goModuleDirectories(t) {
		t.Run(directory, func(t *testing.T) {
			_, ok := tracked[directory]
			assert.Truef(t, ok,
				"a go.mod exists at %s but no %q entry in .github/%s covers it, "+
					"so its dependencies receive no automated CVE patches",
				directory, gomodEcosystem, dependabotConfigName)
		})
	}
}

// TestDependabotTracksGitHubActions guards the supply chain of CI itself: every
// action in .github/workflows is pinned to a commit SHA, so nothing moves them
// off a vulnerable revision unless Dependabot is watching this ecosystem.
func TestDependabotTracksGitHubActions(t *testing.T) {
	config := loadDependabotConfig(t)

	for _, update := range config.Updates {
		if update.PackageEcosystem == actionsEcosystem {
			return
		}
	}

	t.Errorf("no %q entry in .github/%s; the workflows pin actions by commit SHA, "+
		"so without it a pinned action stays on a vulnerable revision indefinitely",
		actionsEcosystem, dependabotConfigName)
}
