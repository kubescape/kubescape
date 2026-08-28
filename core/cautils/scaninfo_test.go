package cautils

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	giturl "github.com/kubescape/go-git-url"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/internal/testutils"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/clientcmd"
)

func TestSetContextMetadata(t *testing.T) {
	t.Run("explicit kubeconfig context", func(t *testing.T) {
		defaultPath := writeScanInfoKubeconfig(t, "context-b")
		explicitPath := writeScanInfoKubeconfig(t, "context-a")
		defaultConfig, err := clientcmd.LoadFromFile(defaultPath)
		require.NoError(t, err)
		k8sinterface.SetClusterContextName("")
		k8sinterface.SetClientConfigAPI(defaultConfig)
		t.Cleanup(func() {
			k8sinterface.SetClientConfigAPI(nil)
			k8sinterface.SetClusterContextName("")
		})

		scanInfo := &ScanInfo{}
		scanInfo.SetKubeconfigSelection(explicitPath, "")
		require.NoError(t, scanInfo.Init(context.Background(), nil))
		require.NoError(t, scanInfo.ResolveClusterContextName())
		metadata := scanInfoToScanMetadata(context.Background(), scanInfo, nil)
		ctx := metadata.ContextMetadata

		require.NotNil(t, ctx.ClusterContextMetadata)
		assert.Equal(t, "context-a", ctx.ClusterContextMetadata.ContextName)
	})

	t.Run("empty input cluster context", func(t *testing.T) {
		ctx := reporthandlingv2.ContextMetadata{}
		scanInfo := &ScanInfo{}
		scanInfo.setContextMetadata(context.Background(), &ctx)

		assert.NotNil(t, ctx.ClusterContextMetadata)
		assert.Nil(t, ctx.DirectoryContextMetadata)
		assert.Nil(t, ctx.FileContextMetadata)
		assert.Nil(t, ctx.HelmContextMetadata)
		assert.Nil(t, ctx.RepoContextMetadata)
	})
	t.Run("git local repository metadata", func(t *testing.T) {
		// metadataGitLocal only parses the local repo's configured remote URL,
		// so a local fixture reproduces the remote metadata without any HTTP calls.
		dir := newGitFixture(t, "https://github.com/kubescape/kubescape")
		ctx := reporthandlingv2.ContextMetadata{}
		scanInfo := &ScanInfo{InputPatterns: []string{dir}}
		scanInfo.setContextMetadata(context.Background(), &ctx)

		assert.Nil(t, ctx.ClusterContextMetadata)
		assert.Nil(t, ctx.DirectoryContextMetadata)
		assert.Nil(t, ctx.FileContextMetadata)
		assert.Nil(t, ctx.HelmContextMetadata)
		assertRepoContextMetadata(t, ctx.RepoContextMetadata, "https://github.com/kubescape/kubescape", dir)
	})
	t.Run("git remote repository metadata", func(t *testing.T) {
		// The ContextGitRemote arm parses the repo that CloneGitRepo cached in
		// tmpDirPaths via metadataGitLocal(GetClonedPath(input)), so
		// pre-registering the clone path avoids any HTTP calls.
		remoteURL := "https://github.com/kubescape/kubescape"
		dir := newGitFixture(t, remoteURL)
		gitURL, err := giturl.NewGitAPI(remoteURL)
		require.NoError(t, err)
		if tmpDirPaths == nil {
			tmpDirPaths = make(map[string]string)
		}
		key := hashRepoURL(gitURL.GetHttpCloneURL())
		tmpDirPaths[key] = dir
		t.Cleanup(func() { delete(tmpDirPaths, key) })

		ctx := reporthandlingv2.ContextMetadata{}
		scanInfo := &ScanInfo{InputPatterns: []string{remoteURL}}
		scanInfo.setContextMetadata(context.Background(), &ctx)

		assert.Nil(t, ctx.ClusterContextMetadata)
		assert.Nil(t, ctx.DirectoryContextMetadata)
		assert.Nil(t, ctx.FileContextMetadata)
		assert.Nil(t, ctx.HelmContextMetadata)
		assertRepoContextMetadata(t, ctx.RepoContextMetadata, remoteURL, dir)
	})
}

func TestScanContractProvenanceUsesFinalPolicySelection(t *testing.T) {
	scanInfo := &ScanInfo{
		ScanContract: &reporthandlingv2.ScanContractMetadata{
			APIVersion:      "config.kubescape.io/v1alpha1",
			Contract:        "ci",
			DigestSchema:    "kubescape-scan-contract:v1",
			ContractDigest:  "sha256:contract",
			AllowedSections: []string{"policy"},
			Effective: &reporthandlingv2.ScanContractEffectiveSettings{
				Policy: &reporthandlingv2.ScanContractPolicy{
					Frameworks: []string{"mitre"},
				},
			},
		},
	}

	metadata := scanInfoToScanMetadata(context.Background(), scanInfo, []PolicyIdentifier{
		{Identifier: "nsa", Kind: apisv1.KindFramework},
		{Identifier: "C-0001", Kind: apisv1.KindControl},
	})
	provenance := metadata.ScanMetadata.ScanContract
	require.NotNil(t, provenance)
	require.NotNil(t, provenance.Effective)
	require.NotNil(t, provenance.Effective.Policy)
	assert.Equal(t, []string{"nsa"}, provenance.Effective.Policy.Frameworks)
	assert.Equal(t, []string{"C-0001"}, provenance.Effective.Policy.Controls)
	assert.Regexp(t, `^sha256:[0-9a-f]{64}$`, provenance.EffectiveRunDigest)
	assert.Equal(t, []string{"mitre"}, scanInfo.ScanContract.Effective.Policy.Frameworks, "report finalization must not mutate the reusable scan input")
}

func TestScanContractProvenanceRecordsConsumedRunnerInputs(t *testing.T) {
	controls := getter.NewLoadPolicy([]string{filepath.Join(testutils.CurrentDir(), "getter", "testdata", "controls-inputs.json")})
	_, err := controls.GetControlsInputs(context.Background(), "")
	require.NoError(t, err)

	exceptions := getter.NewLoadPolicy([]string{filepath.Join(testutils.CurrentDir(), "getter", "testdata", "exceptions.json")})
	_, err = exceptions.GetExceptions(context.Background(), "")
	require.NoError(t, err)

	scanInfo := &ScanInfo{ScanContract: &reporthandlingv2.ScanContractMetadata{
		APIVersion:     "config.kubescape.io/v1alpha1",
		Contract:       "ci",
		DigestSchema:   "kubescape-scan-contract:v1",
		ContractDigest: "sha256:contract",
	}}
	RecordScanContractRunnerInputs(scanInfo, &Getters{
		ControlsInputsGetter: controls,
		ExceptionsGetter:     getter.NewMergedExceptionsGetter(exceptions, nil),
	})

	metadata := scanInfoToScanMetadata(context.Background(), scanInfo, nil)
	provenance := metadata.ScanMetadata.ScanContract
	require.NotNil(t, provenance)
	require.Len(t, provenance.RunnerInputs, 2)
	assert.Equal(t, "controlsConfig", provenance.RunnerInputs[0].Role)
	assert.Equal(t, "exceptions", provenance.RunnerInputs[1].Role)
	for _, input := range provenance.RunnerInputs {
		assert.NotEmpty(t, input.Source)
		assert.False(t, filepath.IsAbs(input.Source))
		assert.Regexp(t, `^sha256:[0-9a-f]{64}$`, input.Digest)
	}
	assert.Regexp(t, `^sha256:[0-9a-f]{64}$`, provenance.EffectiveRunDigest)
}

func TestResolveClusterContextNameRejectsInvalidSelection(t *testing.T) {
	t.Run("missing override", func(t *testing.T) {
		scanInfo := &ScanInfo{}
		scanInfo.SetKubeconfigSelection(writeScanInfoKubeconfig(t, "context-a"), "context-missing")

		err := scanInfo.ResolveClusterContextName()
		require.ErrorContains(t, err, `context "context-missing" does not exist`)
	})

	t.Run("missing override in default kubeconfig", func(t *testing.T) {
		defaultPath := writeScanInfoKubeconfig(t, "context-a")
		t.Setenv(clientcmd.RecommendedConfigPathEnvVar, defaultPath)
		scanInfo := &ScanInfo{}
		scanInfo.SetKubeconfigSelection("", "context-missing")

		err := scanInfo.ResolveClusterContextName()
		require.EqualError(t, err, `context "context-missing" does not exist in kubeconfig`)
	})

	t.Run("missing current context", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config")
		require.NoError(t, os.WriteFile(path, []byte(`apiVersion: v1
kind: Config
clusters:
- name: cluster
  cluster:
    server: https://example.invalid
contexts:
- name: context-a
  context:
    cluster: cluster
`), 0o600))
		scanInfo := &ScanInfo{}
		scanInfo.SetKubeconfigSelection(path, "")

		err := scanInfo.ResolveClusterContextName()
		require.ErrorContains(t, err, `context "" does not exist`)
	})
}

func TestResolveClusterContextNameUsesDefaultLoadingRulesForOverride(t *testing.T) {
	defaultPath := writeScanInfoMultiContextKubeconfig(t)
	t.Setenv(clientcmd.RecommendedConfigPathEnvVar, defaultPath)
	scanInfo := &ScanInfo{}
	scanInfo.SetKubeconfigSelection("", "context-selected")

	require.NoError(t, scanInfo.ResolveClusterContextName())
	assert.True(t, scanInfo.contextResolved)
	assert.Equal(t, "context-selected", scanInfo.GetClusterContextName())
}

func TestResolveClusterContextNameSkipsDefaultLoadingWithoutSelection(t *testing.T) {
	invalidPath := filepath.Join(t.TempDir(), "invalid-config")
	require.NoError(t, os.WriteFile(invalidPath, []byte("not: [valid"), 0o600))
	t.Setenv(clientcmd.RecommendedConfigPathEnvVar, invalidPath)
	scanInfo := &ScanInfo{}
	scanInfo.SetKubeconfigSelection("", "")

	require.NoError(t, scanInfo.ResolveClusterContextName())
	assert.False(t, scanInfo.contextResolved)
}

func writeScanInfoKubeconfig(t *testing.T, contextName string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	contents := fmt.Sprintf(`apiVersion: v1
kind: Config
current-context: %[1]s
clusters:
- name: cluster
  cluster:
    server: https://example.invalid
contexts:
- name: %[1]s
  context:
    cluster: cluster
    user: user
users:
- name: user
  user:
    token: test
`, contextName)
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func writeScanInfoMultiContextKubeconfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	contents := `apiVersion: v1
kind: Config
current-context: context-current
clusters:
- name: cluster-current
  cluster:
    server: https://current.example
- name: cluster-selected
  cluster:
    server: https://selected.example
contexts:
- name: context-current
  context:
    cluster: cluster-current
    user: user
- name: context-selected
  context:
    cluster: cluster-selected
    user: user
users:
- name: user
  user:
    token: test
`
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

// assertRepoContextMetadata verifies every field metadataGitLocal is expected
// to populate, including LastCommit, so regressions like a zeroed committer
// are caught rather than silently shipped in scan reports. The provider,
// repo, owner and remote URL expectations are derived from remoteURL so the
// fixture can be pointed at any repository.
func assertRepoContextMetadata(t *testing.T, meta *reporthandlingv2.RepoContextMetadata, remoteURL, localRoot string) {
	t.Helper()
	require.NotNil(t, meta)
	gitURL, err := giturl.NewGitURL(remoteURL)
	require.NoError(t, err)
	assert.Equal(t, gitURL.GetProvider(), meta.Provider)
	assert.Equal(t, gitURL.GetRepoName(), meta.Repo)
	assert.Equal(t, gitURL.GetOwnerName(), meta.Owner)
	assert.Equal(t, "master", meta.Branch)
	assert.Equal(t, gitURL.GetURL().String(), meta.RemoteURL)
	// go-git resolves symlinks, so on macOS /var/... resolves to /private/var/...
	resolvedRoot, err := filepath.EvalSymlinks(localRoot)
	require.NoError(t, err)
	assert.Equal(t, resolvedRoot, meta.LocalRootPath)
	assert.NotEmpty(t, meta.LastCommit.Hash)
	assert.Equal(t, "kubescape", meta.LastCommit.CommitterName)
	assert.NotZero(t, meta.LastCommit.Date)
}

// newGitFixture creates a local git repository with a single commit, an
// "origin" remote pointing at remoteURL, and an explicit "master" default
// branch (rather than relying on go-git's implicit default), returning its
// working directory.
func newGitFixture(t *testing.T, remoteURL string) string {
	t.Helper()
	dir := t.TempDir()
	repo, err := git.PlainInitWithOptions(dir, &git.PlainInitOptions{
		InitOptions: git.InitOptions{DefaultBranch: plumbing.Master},
	})
	require.NoError(t, err)
	_, err = repo.CreateRemote(&config.RemoteConfig{
		Name: "origin",
		URLs: []string{remoteURL},
	})
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte("# test\n"), 0600))
	worktree, err := repo.Worktree()
	require.NoError(t, err)
	_, err = worktree.Add("README.md")
	require.NoError(t, err)
	_, err = worktree.Commit("initial commit", &git.CommitOptions{
		Author: &object.Signature{Name: "kubescape", Email: "kubescape@example.com", When: time.Now()},
	})
	require.NoError(t, err)
	return dir
}

func TestGetHostname(t *testing.T) {
	// Test that the hostname is not empty
	assert.NotEqual(t, "", getHostname())
}

func TestGetScanningContext(t *testing.T) {
	repoRoot, err := os.MkdirTemp("", "repo")
	require.NoError(t, err)
	defer func(name string) {
		_ = os.Remove(name)
	}(repoRoot)
	_, err = git.PlainClone(repoRoot, false, &git.CloneOptions{
		URL: "https://github.com/kubescape/http-request",
	})
	require.NoError(t, err)
	tmpFile, err := os.CreateTemp("", "single.*.txt")
	require.NoError(t, err)
	defer func(name string) {
		_ = os.Remove(name)
	}(tmpFile.Name())
	tests := []struct {
		name  string
		input string
		want  ScanningContext
	}{
		{
			name:  "empty input",
			input: "",
			want:  ContextCluster,
		},
		{
			name:  "git URL input",
			input: "https://github.com/kubescape/http-request",
			want:  ContextGitRemote,
		},
		{
			name:  "local git input",
			input: repoRoot,
			want:  ContextGitLocal,
		},
		{
			name:  "single file input",
			input: tmpFile.Name(),
			want:  ContextFile,
		},
		{
			name:  "directory input",
			input: os.TempDir(),
			want:  ContextDir,
		},
		{
			name:  "self-hosted GitLab URL that can't be cloned",
			input: "https://gitlab.private-domain.com/my-org/my-repo.git",
			want:  ContextDir, // Should return ContextDir when clone fails, not try to treat as local path
		},
		{
			name:  "http URL that can't be cloned",
			input: "http://gitlab.example.com/org/repo",
			want:  ContextDir, // Should return ContextDir when clone fails, not try to treat as local path
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanInfo := &ScanInfo{}
			assert.Equalf(t, tt.want, scanInfo.getScanningContext(tt.input), "GetScanningContext(%v)", tt.input)
		})
	}
}

// TestGetScanningContextLinkedWorktree covers the user-visible half of the linked
// worktree bug: the metadata loss is silent precisely because the scan still succeeds,
// having been classified as a plain directory rather than as a local git repository.
// It is kept out of the TestGetScanningContext table so it stays hermetic — that table
// clones over the network, and this case needs nothing but a temp directory.
func TestGetScanningContextLinkedWorktree(t *testing.T) {
	fixture := createLinkedWorktreeFixture(t, "feature", "https://github.com/kubescape/worktree-fixture.git")

	scanInfo := &ScanInfo{}
	assert.Equal(t, ContextGitLocal, scanInfo.getScanningContext(fixture.worktreeRoot))
}

func TestScanInfoFormats(t *testing.T) {
	testCases := []struct {
		name  string
		Input string
		Want  []string
	}{
		{"empty string", "", []string{}},
		{"single json", "json", []string{"json"}},
		{"single pdf", "pdf", []string{"pdf"}},
		{"single html", "html", []string{"html"}},
		{"single sarif", "sarif", []string{"sarif"}},
		{"multiple formats", "html,pdf,sarif", []string{"html", "pdf", "sarif"}},
		{"pretty-printer with others", "pretty-printer,pdf,sarif", []string{"pretty-printer", "pdf", "sarif"}},
		{"consecutive commas", "json,,pdf", []string{"json", "pdf"}},
		{"whitespace-only entry", "json, ,pdf", []string{"json", "pdf"}},
		{"trailing comma", "json,pdf,", []string{"json", "pdf"}},
		{"leading comma", ",json,pdf", []string{"json", "pdf"}},
		{"only commas", ",,,", []string{}},
		{"whitespace around formats", " json , pdf ", []string{"json", "pdf"}},
		{"duplicates preserved order", "json,pdf,json", []string{"json", "pdf"}},
		{"duplicates with whitespace", "json, json ,pdf", []string{"json", "pdf"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scanInfo := &ScanInfo{Format: tc.Input}

			got := scanInfo.Formats()

			assert.Equal(t, tc.Want, got)
		})
	}
}

func TestScanInfoFormatsDeduplicatesInOrder(t *testing.T) {
	testCases := []struct {
		name   string
		format string
		want   []string
	}{
		{
			name:   "duplicate json",
			format: "json,json",
			want:   []string{"json"},
		},
		{
			name:   "keeps first occurrence order",
			format: "json,pdf,json,sarif,pdf",
			want:   []string{"json", "pdf", "sarif"},
		},
		{
			name:   "trims whitespace and deduplicates",
			format: "json, json,json",
			want:   []string{"json"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scanInfo := &ScanInfo{Format: tc.format}

			assert.Equal(t, tc.want, scanInfo.Formats())
		})
	}
}

func TestScanInfoToScanMetadataFormats(t *testing.T) {
	testCases := []struct {
		name   string
		format string
		want   []string
	}{
		{
			name:   "multiple formats are separate metadata entries",
			format: "json,junit,html",
			want:   []string{"json", "junit", "html"},
		},
		{
			name:   "formats are trimmed and deduplicated",
			format: " json, ,pdf,json,pdf ",
			want:   []string{"json", "pdf"},
		},
		{
			name:   "single format is preserved",
			format: "sarif",
			want:   []string{"sarif"},
		},
		{
			name:   "empty format does not produce an empty metadata entry",
			format: "",
			want:   []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scanInfo := &ScanInfo{Format: tc.format}

			metadata := scanInfoToScanMetadata(context.Background(), scanInfo, nil)

			assert.Equal(t, tc.want, metadata.ScanMetadata.Formats)
		})
	}
}

func TestAppendPolicyIdentifiers(t *testing.T) {
	tests := []struct {
		name     string
		existing []PolicyIdentifier
		policies []string
		want     []PolicyIdentifier
	}{
		{
			name:     "adds new policies",
			policies: []string{"nsa", "mitre"},
			want: []PolicyIdentifier{
				{Identifier: "nsa", Kind: apisv1.KindFramework},
				{Identifier: "mitre", Kind: apisv1.KindFramework},
			},
		},
		{
			name: "skips existing policy",
			existing: []PolicyIdentifier{
				{Identifier: "nsa", Kind: apisv1.KindFramework},
			},
			policies: []string{"nsa", "mitre"},
			want: []PolicyIdentifier{
				{Identifier: "nsa", Kind: apisv1.KindFramework},
				{Identifier: "mitre", Kind: apisv1.KindFramework},
			},
		},
		{
			name:     "empty policy list leaves existing values",
			existing: []PolicyIdentifier{{Identifier: "C-0001", Kind: apisv1.KindControl}},
			want:     []PolicyIdentifier{{Identifier: "C-0001", Kind: apisv1.KindControl}},
		},
		{
			name: "skips existing policy regardless of case",
			existing: []PolicyIdentifier{
				{Identifier: "nsa", Kind: apisv1.KindFramework},
			},
			policies: []string{"NSA", "MITRE"},
			want: []PolicyIdentifier{
				{Identifier: "nsa", Kind: apisv1.KindFramework},
				{Identifier: "MITRE", Kind: apisv1.KindFramework},
			},
		},
		{
			name:     "deduplicates differently cased policies within the same list",
			policies: []string{"nsa", "NSA"},
			want: []PolicyIdentifier{
				{Identifier: "nsa", Kind: apisv1.KindFramework},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policyIdentifiers := AppendPolicyIdentifiers(tt.existing, tt.policies, apisv1.KindFramework)

			assert.Equal(t, tt.want, policyIdentifiers)
		})
	}
}

func TestSetUseFrom(t *testing.T) {
	cachePath := func(identifier string) string {
		path, err := getter.PolicyCachePath(identifier)
		require.NoError(t, err)
		return path
	}

	tests := []struct {
		name              string
		scanInfo          *ScanInfo
		policyIdentifiers []PolicyIdentifier
		want              []string
	}{
		{
			name:              "resolves a cache path per identifier",
			scanInfo:          &ScanInfo{UseDefault: true},
			policyIdentifiers: BuildPolicyIdentifiers([]string{"nsa", "mitre"}, apisv1.KindFramework),
			want:              []string{cachePath("nsa"), cachePath("mitre")},
		},
		{
			name:              "resolves every identifier a ScanAll expansion contributed",
			scanInfo:          &ScanInfo{UseDefault: true, ScanAll: true},
			policyIdentifiers: BuildPolicyIdentifiers([]string{"allcontrols", "nsa", "mitre"}, apisv1.KindFramework),
			want:              []string{cachePath("allcontrols"), cachePath("nsa"), cachePath("mitre")},
		},
		{
			name:              "skips identifiers that cannot be turned into a cache path",
			scanInfo:          &ScanInfo{UseDefault: true},
			policyIdentifiers: BuildPolicyIdentifiers([]string{"../etc/passwd", "nsa"}, apisv1.KindFramework),
			want:              []string{cachePath("nsa")},
		},
		{
			name:              "without UseDefault nothing is resolved",
			scanInfo:          &ScanInfo{},
			policyIdentifiers: BuildPolicyIdentifiers([]string{"nsa"}, apisv1.KindFramework),
			want:              nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.scanInfo.setUseFrom(tt.policyIdentifiers)

			assert.Equal(t, tt.want, tt.scanInfo.UseFrom)
		})
	}
}

func TestSetUseArtifactsFrom(t *testing.T) {
	t.Run("directory whose name contains .json is kept as-is", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "my.json-artifacts")
		require.NoError(t, os.MkdirAll(dir, 0755))

		scanInfo := &ScanInfo{UseArtifactsFrom: dir}
		require.NoError(t, scanInfo.setUseArtifactsFrom(context.Background()))

		assert.Equal(t, dir, scanInfo.UseArtifactsFrom)
	})

	t.Run("a file path falls back to its parent directory", func(t *testing.T) {
		parent := t.TempDir()
		file := filepath.Join(parent, "controls-inputs.json")
		require.NoError(t, os.WriteFile(file, []byte(`{}`), 0600))

		scanInfo := &ScanInfo{UseArtifactsFrom: file}
		require.NoError(t, scanInfo.setUseArtifactsFrom(context.Background()))

		assert.Equal(t, parent, scanInfo.UseArtifactsFrom)
	})

	t.Run("bare filename without separator is left untouched", func(t *testing.T) {
		t.Chdir(t.TempDir()) // hermetic: behavior must not depend on the package dir contents

		scanInfo := &ScanInfo{UseArtifactsFrom: "controls-inputs.json"}
		require.Error(t, scanInfo.setUseArtifactsFrom(context.Background()))
		assert.Equal(t, "controls-inputs.json", scanInfo.UseArtifactsFrom)
	})

	t.Run("explicit current-directory file path falls back to .", func(t *testing.T) {
		t.Chdir(t.TempDir()) // hermetic: behavior must not depend on the package dir contents
		require.NoError(t, os.WriteFile("./controls-inputs.json", []byte(`{}`), 0600))

		scanInfo := &ScanInfo{UseArtifactsFrom: "./controls-inputs.json"}
		require.NoError(t, scanInfo.setUseArtifactsFrom(context.Background()))

		assert.Equal(t, ".", scanInfo.UseArtifactsFrom)
	})

	t.Run("nonexistent path is left untouched", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing")
		scanInfo := &ScanInfo{UseArtifactsFrom: path}
		require.Error(t, scanInfo.setUseArtifactsFrom(context.Background()))
		assert.Equal(t, path, scanInfo.UseArtifactsFrom)
	})
}

// TestInitDeduplicatesUseFrom covers the offline HTTP handler configuration, where UseDefault
// and UseArtifactsFrom both point at the local store: setUseFrom resolves a cache path per
// identifier and setUseArtifactsFrom then discovers the very same file by reading the directory.
// The local store is redirected at the temporary directory so both sources genuinely collide.
func TestInitDeduplicatesUseFrom(t *testing.T) {
	artifactsDir := t.TempDir()
	framework := []byte(`{"name":"nsa","controls":[]}`)
	require.NoError(t, os.WriteFile(filepath.Join(artifactsDir, "nsa.json"), framework, 0600))

	prevStore := getter.DefaultLocalStore
	getter.DefaultLocalStore = artifactsDir
	t.Cleanup(func() { getter.DefaultLocalStore = prevStore })

	scanInfo := &ScanInfo{
		UseDefault:       true,
		UseArtifactsFrom: artifactsDir,
	}
	require.NoError(t, scanInfo.Init(context.Background(), BuildPolicyIdentifiers([]string{"nsa"}, apisv1.KindFramework)))

	assert.Equal(t, []string{filepath.Join(artifactsDir, "nsa.json")}, scanInfo.UseFrom)
}

func TestSplitNamespaceList(t *testing.T) {
	testCases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"single", "ns-a", []string{"ns-a"}},
		{"multiple", "ns-a,ns-b,ns-c", []string{"ns-a", "ns-b", "ns-c"}},
		{"whitespace", "ns-a, ns-b ,ns-c", []string{"ns-a", "ns-b", "ns-c"}},
		{"empty entries dropped", "ns-a,,ns-b,", []string{"ns-a", "ns-b"}},
		{"only commas", ",,,", nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, splitNamespaceList(tc.in))
		})
	}
}

func TestScanInfoToScanMetadataNamespaces(t *testing.T) {
	t.Run("populates excluded namespaces", func(t *testing.T) {
		scanInfo := &ScanInfo{ExcludedNamespaces: "kube-system,kube-public"}
		md := scanInfoToScanMetadata(context.Background(), scanInfo, nil)
		assert.Equal(t, []string{"kube-system", "kube-public"}, md.ScanMetadata.ExcludedNamespaces)
		assert.Empty(t, md.ScanMetadata.IncludeNamespaces)
	})

	t.Run("populates included namespaces", func(t *testing.T) {
		scanInfo := &ScanInfo{IncludeNamespaces: "default,prod"}
		md := scanInfoToScanMetadata(context.Background(), scanInfo, nil)
		assert.Equal(t, []string{"default", "prod"}, md.ScanMetadata.IncludeNamespaces)
		assert.Empty(t, md.ScanMetadata.ExcludedNamespaces)
	})

	t.Run("empty when not set", func(t *testing.T) {
		scanInfo := &ScanInfo{}
		md := scanInfoToScanMetadata(context.Background(), scanInfo, nil)
		assert.Empty(t, md.ScanMetadata.ExcludedNamespaces)
		assert.Empty(t, md.ScanMetadata.IncludeNamespaces)
	})
}
