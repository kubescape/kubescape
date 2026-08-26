package cautils

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	giturl "github.com/kubescape/go-git-url"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPathFilterExcluded(t *testing.T) {
	root := t.TempDir()

	tests := []struct {
		name     string
		patterns []string
		path     string
		isDir    bool
		want     bool
	}{
		{
			name:     "basename matches at any depth",
			patterns: []string{"secret.yaml"},
			path:     "deploy/overlays/secret.yaml",
			want:     true,
		},
		{
			name:     "basename matches at the root",
			patterns: []string{"secret.yaml"},
			path:     "secret.yaml",
			want:     true,
		},
		{
			name:     "unrelated path is kept",
			patterns: []string{"secret.yaml"},
			path:     "deploy/deployment.yaml",
			want:     false,
		},
		{
			name:     "wildcard matches the extension",
			patterns: []string{"*.json"},
			path:     "manifests/pod.json",
			want:     true,
		},
		{
			name:     "directory pattern excludes its contents",
			patterns: []string{"testdata/"},
			path:     "testdata/fixtures/pod.yaml",
			want:     true,
		},
		{
			name:     "directory pattern does not match a file of the same name",
			patterns: []string{"testdata/"},
			path:     "testdata",
			want:     false,
		},
		{
			name:     "directory pattern matches the directory itself",
			patterns: []string{"testdata/"},
			path:     "testdata",
			isDir:    true,
			want:     true,
		},
		{
			name:     "anchored pattern only matches at the root",
			patterns: []string{"/vendor"},
			path:     "charts/vendor/pod.yaml",
			want:     false,
		},
		{
			name:     "anchored pattern matches at the root",
			patterns: []string{"/vendor"},
			path:     "vendor/pod.yaml",
			want:     true,
		},
		{
			name:     "embedded separator anchors the pattern",
			patterns: []string{"charts/values.yaml"},
			path:     "charts/values.yaml",
			want:     true,
		},
		{
			name:     "embedded separator does not match deeper",
			patterns: []string{"charts/values.yaml"},
			path:     "nested/charts/values.yaml",
			want:     false,
		},
		{
			name:     "doublestar spans directories",
			patterns: []string{"charts/**/values.yaml"},
			path:     "charts/redis/subchart/values.yaml",
			want:     true,
		},
		{
			name:     "leading doublestar matches at any depth",
			patterns: []string{"**/generated/*.yaml"},
			path:     "apps/web/generated/pod.yaml",
			want:     true,
		},
		{
			name:     "later pattern wins over an earlier one",
			patterns: []string{"test/**", "!test/prod.yaml"},
			path:     "test/prod.yaml",
			want:     false,
		},
		{
			name:     "negation is limited to what it names",
			patterns: []string{"test/**", "!test/prod.yaml"},
			path:     "test/dev.yaml",
			want:     true,
		},
		{
			name:     "descendant pattern keeps the directory scannable",
			patterns: []string{"test/**"},
			path:     "test",
			isDir:    true,
			want:     false,
		},
		{
			name:     "negation survives a descendant prefix carrying glob metadata",
			patterns: []string{"**/build/**", "!**/build/final.yaml"},
			path:     "sub/build/final.yaml",
			want:     false,
		},
		{
			name:     "a glob-metadata descendant prefix still excludes its other contents",
			patterns: []string{"**/build/**", "!**/build/final.yaml"},
			path:     "sub/build/other.yaml",
			want:     true,
		},
		{
			name:     "repeated trailing globstars do not exempt the contents",
			patterns: []string{"build/**/**"},
			path:     "build/other.yaml",
			want:     true,
		},
		{
			name:     "an excluded directory cannot be re-included from below",
			patterns: []string{"test/", "!test/prod.yaml"},
			path:     "test/prod.yaml",
			want:     true,
		},
		{
			name:     "comments and blank lines carry no rule",
			patterns: []string{"# secret.yaml", "   ", "pod.yaml"},
			path:     "secret.yaml",
			want:     false,
		},
		{
			name:     "trailing separators are normalized",
			patterns: []string{"testdata///"},
			path:     "testdata/pod.yaml",
			want:     true,
		},
		{
			name:     "explicit relative prefix is accepted",
			patterns: []string{"./testdata"},
			path:     "testdata/pod.yaml",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter, err := NewPathFilter(root, tt.patterns)
			require.NoError(t, err)
			require.NotNil(t, filter)

			got := filter.Excluded(filepath.Join(root, filepath.FromSlash(tt.path)), tt.isDir)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPathFilterIgnoresPathsOutsideRoot(t *testing.T) {
	root := t.TempDir()
	filter, err := NewPathFilter(root, []string{"pod.yaml"})
	require.NoError(t, err)

	assert.False(t, filter.Excluded(filepath.Join(filepath.Dir(root), "pod.yaml"), false))
	assert.False(t, filter.Excluded(root, true))
}

func TestPathFilterNilIsInert(t *testing.T) {
	var filter *PathFilter

	assert.False(t, filter.Excluded("/any/path.yaml", false))
	assert.Nil(t, filter.Patterns())
	assert.Empty(t, filter.Root())
}

func TestNewPathFilterRejectsMalformedPatterns(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr error
	}{
		{name: "unclosed character class", pattern: "pod[.yaml", wantErr: ErrInvalidIgnorePattern},
		{name: "negation with no pattern", pattern: "!", wantErr: ErrEmptyIgnorePattern},
		{name: "separator only", pattern: "/", wantErr: ErrEmptyIgnorePattern},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter, err := NewPathFilter(t.TempDir(), []string{tt.pattern})
			require.ErrorIs(t, err, tt.wantErr)
			assert.Nil(t, filter)
		})
	}
}

func TestNewPathFilterWithoutRulesReturnsNil(t *testing.T) {
	filter, err := NewPathFilter(t.TempDir(), []string{"# only a comment", ""})
	require.NoError(t, err)
	assert.Nil(t, filter)
}

func TestNewScanPathFilterReadsIgnoreFile(t *testing.T) {
	root := t.TempDir()
	writeIgnoreFile(t, root, "# generated manifests\ngenerated/\n\n*.tmpl.yaml\n")

	filter, err := NewScanPathFilter(root, nil, true)
	require.NoError(t, err)
	require.NotNil(t, filter)

	assert.Equal(t, []string{"generated/", "*.tmpl.yaml"}, filter.Patterns())
	assert.True(t, filter.Excluded(filepath.Join(root, "generated", "pod.yaml"), false))
	assert.True(t, filter.Excluded(filepath.Join(root, "deploy", "pod.tmpl.yaml"), false))
	assert.False(t, filter.Excluded(filepath.Join(root, "deploy", "pod.yaml"), false))
}

func TestNewScanPathFilterCommandLinePatternsWinOverIgnoreFile(t *testing.T) {
	root := t.TempDir()
	writeIgnoreFile(t, root, "test/**\n")

	filter, err := NewScanPathFilter(root, []string{"!test/prod.yaml"}, true)
	require.NoError(t, err)
	require.NotNil(t, filter)

	assert.False(t, filter.Excluded(filepath.Join(root, "test", "prod.yaml"), false))
	assert.True(t, filter.Excluded(filepath.Join(root, "test", "dev.yaml"), false))
}

func TestNewScanPathFilterSkipsIgnoreFileWhenDisabled(t *testing.T) {
	root := t.TempDir()
	writeIgnoreFile(t, root, "test/**\n")

	filter, err := NewScanPathFilter(root, nil, false)
	require.NoError(t, err)
	assert.Nil(t, filter)
}

func TestNewScanPathFilterAnchorsAFileInputAtItsDirectory(t *testing.T) {
	root := t.TempDir()
	writeIgnoreFile(t, root, "skipped.yaml\n")
	manifest := filepath.Join(root, "pod.yaml")
	require.NoError(t, os.WriteFile(manifest, []byte("kind: Pod\n"), 0o600))

	filter, err := NewScanPathFilter(manifest, nil, true)
	require.NoError(t, err)
	require.NotNil(t, filter)

	assert.Equal(t, filepath.Clean(root), filter.Root())
	assert.True(t, filter.Excluded(filepath.Join(root, "skipped.yaml"), false))
}

func TestLoadIgnoreFilePatternsWithoutFile(t *testing.T) {
	patterns, err := LoadIgnoreFilePatterns(t.TempDir())
	require.NoError(t, err)
	assert.Empty(t, patterns)
}

func writeIgnoreFile(t *testing.T, root, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(root, IgnoreFileName), []byte(content), 0o600))
}

func TestLoadResourcesFromFilesFilteredSkipsExcludedManifests(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "testdata"), 0o750))
	writeManifest(t, filepath.Join(root, "pod.yaml"), "scanned")
	writeManifest(t, filepath.Join(root, "testdata", "pod.yaml"), "fixture")

	filter, err := NewPathFilter(root, []string{"testdata/"})
	require.NoError(t, err)

	workloads, _, err := LoadResourcesFromFilesFiltered(context.Background(), root, root, nil, filter)
	require.NoError(t, err)
	require.Len(t, workloads, 1)

	for source := range workloads {
		assert.Equal(t, filepath.Join(root, "pod.yaml"), source)
	}
}

func TestLoadResourcesFromFilesFilteredRejectsAnExcludedFileInput(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "pod.yaml")
	writeManifest(t, manifest, "scanned")

	filter, err := NewPathFilter(root, []string{"pod.yaml"})
	require.NoError(t, err)

	_, _, err = LoadResourcesFromFilesFiltered(context.Background(), manifest, root, nil, filter)
	require.ErrorIs(t, err, ErrNoManifestFiles)
	assert.Contains(t, err.Error(), "path exclusions are in effect")
}

func TestLoadResourcesFromHelmChartsFilteredSkipsExcludedCharts(t *testing.T) {
	root := filepath.Join("testdata", "helm_chart_layout")

	filter, err := NewPathFilter(root, []string{"mychart/"})
	require.NoError(t, err)

	workloads, charts, rendered, err := LoadResourcesFromHelmChartsFiltered(context.Background(), root, HelmValueOptions{}, nil, filter)
	require.NoError(t, err)
	assert.Empty(t, workloads)
	assert.Empty(t, charts)
	assert.Empty(t, rendered)
}

func TestLoadResourcesFromHelmChartsFilteredKeepsUnexcludedCharts(t *testing.T) {
	root := filepath.Join("testdata", "helm_chart_layout")

	filter, err := NewPathFilter(root, []string{"plain-pod.yaml"})
	require.NoError(t, err)

	_, charts, rendered, err := LoadResourcesFromHelmChartsFiltered(context.Background(), root, HelmValueOptions{}, nil, filter)
	require.NoError(t, err)
	assert.NotEmpty(t, charts)
	assert.NotEmpty(t, rendered)
}

func writeManifest(t *testing.T, path, name string) {
	t.Helper()
	manifest := "apiVersion: v1\nkind: Pod\nmetadata:\n  name: " + name + "\n  namespace: default\n"
	require.NoError(t, os.WriteFile(path, []byte(manifest), 0o600))
}

// TestPathFilterMatchesGitignoreSemantics checks the syntax promise the flag help makes,
// against git itself.
func TestPathFilterMatchesGitignoreSemantics(t *testing.T) {
	patterns := []string{
		"test/", "!test/prod.yaml",
		"*.tmpl.yaml", "!keep.tmpl.yaml",
		"/vendor",
		"**/generated/",
		"charts/*/values.yaml",
		"a/**/b.yaml",
		"node_modules",
		"build/**", "!build/final.yaml",
		"**/dist/**", "!**/dist/final.yaml",
		"a/*/gen/**", "!a/*/gen/keep.yaml",
	}
	paths := []string{
		"pod.yaml", "test/prod.yaml", "test/dev.yaml", "test/deep/x.yaml",
		"app.tmpl.yaml", "keep.tmpl.yaml", "sub/keep.tmpl.yaml",
		"vendor/x.yaml", "sub/vendor/x.yaml",
		"generated/x.yaml", "a/generated/x.yaml",
		"charts/redis/values.yaml", "charts/a/b/values.yaml",
		"a/b.yaml", "a/x/b.yaml", "a/x/y/b.yaml",
		"node_modules/p.yaml", "sub/node_modules/p.yaml",
		"build/final.yaml", "build/other.yaml", "build/deep/final.yaml",
		"dist/final.yaml", "dist/other.yaml",
		"sub/dist/final.yaml", "sub/dist/other.yaml", "deep/sub/dist/final.yaml",
		"a/x/gen/keep.yaml", "a/x/gen/drop.yaml",
	}

	root := t.TempDir()
	// Pin git to an empty configuration; a global core.excludesFile would otherwise
	// decide part of the comparison.
	noConfig := filepath.Join(t.TempDir(), "gitconfig-none")
	git := func(args ...string) *exec.Cmd {
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...) //nolint:gosec // G204: test-only; args are literals from this test and root is a t.TempDir().
		cmd.Env = append(os.Environ(),
			"GIT_CONFIG_GLOBAL="+noConfig,
			"GIT_CONFIG_SYSTEM="+noConfig,
			"GIT_CONFIG_NOSYSTEM=1",
		)
		return cmd
	}
	if out, err := git("init", "-q").CombinedOutput(); err != nil {
		t.Skipf("git is unavailable: %v: %s", err, out)
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, ".gitignore"), []byte(strings.Join(patterns, "\n")+"\n"), 0o600))
	for _, path := range paths {
		full := filepath.Join(root, filepath.FromSlash(path))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o750))
		require.NoError(t, os.WriteFile(full, []byte("kind: Pod\n"), 0o600))
	}

	filter, err := NewPathFilter(root, patterns)
	require.NoError(t, err)
	require.NotNil(t, filter)

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			gitIgnores := git("check-ignore", "-q", path).Run() == nil
			assert.Equal(t, gitIgnores, filter.Excluded(filepath.Join(root, filepath.FromSlash(path)), false))
		})
	}
}

func TestNewScanPathFilterAnchorsAGlobInputAtItsLiteralDirectory(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "manifests"), 0o750))
	writeIgnoreFile(t, filepath.Join(root, "manifests"), "app/**\n")

	filter, err := NewScanPathFilter(filepath.Join(root, "manifests", "**", "*.yaml"), nil, true)
	require.NoError(t, err)
	require.NotNil(t, filter)

	assert.Equal(t, filepath.Join(root, "manifests"), filter.Root())
	assert.True(t, filter.Excluded(filepath.Join(root, "manifests", "app", "pod.yaml"), false))
}

// A repository input is scanned from its clone, so the filter has to anchor there too:
// the ignore file lives in the clone, not next to the URL the user typed.
func TestNewScanPathFilterAnchorsARepositoryInputAtItsClone(t *testing.T) {
	const repoURL = "https://github.com/kubescape/example-path-filter"

	clone := t.TempDir()
	writeIgnoreFile(t, clone, "testdata/\n")

	gitURL, err := giturl.NewGitAPI(repoURL)
	require.NoError(t, err)
	key := repoWorkspaceKey(gitURL)

	tmpDirPathsMu.Lock()
	tmpDirPaths[key] = clone
	tmpDirPathsMu.Unlock()
	t.Cleanup(func() {
		tmpDirPathsMu.Lock()
		delete(tmpDirPaths, key)
		tmpDirPathsMu.Unlock()
	})

	filter, err := NewScanPathFilter(repoURL, nil, true)
	require.NoError(t, err)
	require.NotNil(t, filter)

	assert.Equal(t, filepath.Clean(clone), filter.Root())
	assert.True(t, filter.Excluded(filepath.Join(clone, "testdata", "pod.yaml"), false))
	assert.False(t, filter.Excluded(filepath.Join(clone, "pod.yaml"), false))
}
