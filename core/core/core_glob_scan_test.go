package core

// Regression test for glob-input report roots. Lives in core/core because the
// Windows CI job runs this package, and the in-repository case fails on Windows only.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/kubescape/kubescape/v4/core/cautils"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/reporthandling"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// globScanFixture writes k8s/pod.yaml and k8s/sub/pod.yaml, plus an offline
// framework with one control that fails on hostNetwork. File discovery walks the
// directory part of a glob recursively and matches the last element against base
// names, so "k8s/*.yaml" reads both Pods, exactly as a scan of "k8s" does. The
// nested Pod pins that recursion and a relative path with a subdirectory in it.
func globScanFixture(t *testing.T, root string) (manifests string, scan func(input string) *cautils.OPASessionObj) {
	t.Helper()
	manifests = filepath.Join(root, "k8s")
	require.NoError(t, os.MkdirAll(filepath.Join(manifests, "sub"), 0o755))
	pod := func(name string) []byte {
		return []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: " + name + "\n  namespace: shop\nspec:\n  hostNetwork: true\n  containers:\n  - name: c\n    image: nginx\n")
	}
	require.NoError(t, os.WriteFile(filepath.Join(manifests, "pod.yaml"), pod("top"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(manifests, "sub", "pod.yaml"), pod("nested"), 0o600))

	policyDir := t.TempDir()
	control := agentRuntimeIntegrationControl("C-9001", "Host network", "host-network", reporthandling.RuleMatchObjects{
		APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Pod"},
	}, `object.get(resource.spec, "hostNetwork", false) == true`, "spec.hostNetwork")
	framework := reporthandling.Framework{Controls: []reporthandling.Control{control}}
	framework.Name = "GlobRoot"
	frameworkBytes, err := json.Marshal(framework)
	require.NoError(t, err)
	frameworkPath := filepath.Join(policyDir, "framework.json")
	require.NoError(t, os.WriteFile(frameworkPath, frameworkBytes, 0o600))
	controlsInputs := writeAgentRuntimeScanFile(t, policyDir, "controls-inputs.json", `{}`)
	exceptions := writeAgentRuntimeScanFile(t, policyDir, "exceptions.json", `[]`)
	attackTracks := writeAgentRuntimeScanFile(t, policyDir, "attack-tracks.json", `[]`)

	return manifests, func(input string) *cautils.OPASessionObj {
		t.Helper()
		scanInfo := &cautils.ScanInfo{
			UseFrom:        []string{frameworkPath},
			ControlsInputs: controlsInputs,
			UseExceptions:  exceptions,
			AttackTracks:   attackTracks,
			InputPatterns:  []string{input},
			Local:          true,
			FrameworkScan:  true,
			ScanType:       cautils.ScanTypeFramework,
		}
		scanInfo.Submit.SetBool(false)
		results, err := NewKubescape(context.Background()).Scan(scanInfo, []cautils.PolicyIdentifier{{Identifier: framework.Name, Kind: apisv1.KindFramework}})
		require.NoError(t, err)
		require.NotNil(t, results.GetData())
		return results.GetData()
	}
}

// reportedRoot is the base path a report records, which kubescape fix and the
// SARIF printer resolve relative paths against.
func reportedRoot(data *cautils.OPASessionObj) (reporthandlingv2.ScanningTarget, string) {
	md := data.Metadata
	switch {
	case md.ContextMetadata.RepoContextMetadata != nil && md.ScanMetadata.ScanningTarget == reporthandlingv2.GitLocal:
		return md.ScanMetadata.ScanningTarget, md.ContextMetadata.RepoContextMetadata.LocalRootPath
	case md.ContextMetadata.DirectoryContextMetadata != nil:
		return md.ScanMetadata.ScanningTarget, md.ContextMetadata.DirectoryContextMetadata.BasePath
	}
	return md.ScanMetadata.ScanningTarget, ""
}

type globScanView struct {
	target      reporthandlingv2.ScanningTarget
	root        string
	repo        string   // RepoContextMetadata.Repo, the identity a submitted report is filed under
	sourceRoots []string // ResourceSource.Path of each resource
	relPaths    []string // ResourceSource.RelativePath of each resource, slash-separated
	resources   []string
}

func viewOf(data *cautils.OPASessionObj) globScanView {
	var v globScanView
	v.target, v.root = reportedRoot(data)
	if repo := data.Metadata.ContextMetadata.RepoContextMetadata; repo != nil {
		v.repo = repo.Provider + "/" + repo.Owner + "/" + repo.Repo
	}
	for id, src := range data.ResourceSource {
		v.sourceRoots = append(v.sourceRoots, src.Path)
		v.relPaths = append(v.relPaths, filepath.ToSlash(src.RelativePath))
		v.resources = append(v.resources, id)
	}
	sort.Strings(v.sourceRoots)
	sort.Strings(v.relPaths)
	sort.Strings(v.resources)
	return v
}

// assertReportedAt checks that a scan reports wantRoot as its base path, anchors
// every resource there, and gives each resource a relative path inside that root.
func assertReportedAt(t *testing.T, v globScanView, wantTarget reporthandlingv2.ScanningTarget, wantRoot string, wantRel ...string) {
	t.Helper()
	assert.Equal(t, wantTarget, v.target, "scanning target")
	assert.Equal(t, wantRoot, v.root, "report root")
	assert.NotEmpty(t, v.repo, "repository identity")
	for _, src := range v.sourceRoots {
		assert.Equal(t, wantRoot, src, "resource source root")
	}
	for _, rel := range v.relPaths {
		assert.False(t, rel == ".." || strings.HasPrefix(rel, "../"), "relative path %q leaves the report root", rel)
	}
	sort.Strings(wantRel)
	assert.Equal(t, wantRel, v.relPaths, "relative paths")
}

// A glob input reads the files below its directory, so it must be reported
// exactly as a scan of that directory is: the same scanning target and root, the
// same source paths, and the same resource IDs. Relative paths that leave the
// root make GitLab SAST drop the findings and kubescape fix refuse the report.
func TestScanGlobInputIsReportedLikeItsDirectory(t *testing.T) {
	t.Run("outside a repository", func(t *testing.T) {
		root := t.TempDir()
		if _, err := cautils.GetGitRootDir(root); err == nil {
			t.Skip("the temporary directory is inside a git checkout")
		}
		manifests, scan := globScanFixture(t, root)
		dir := viewOf(scan(manifests))
		assertReportedAt(t, dir, reporthandlingv2.Directory, manifests, "pod.yaml", "sub/pod.yaml")
		glob := viewOf(scan(filepath.Join(manifests, "*.yaml")))
		assertReportedAt(t, glob, reporthandlingv2.Directory, manifests, "pod.yaml", "sub/pod.yaml")
		assert.Equal(t, dir, glob)
	})

	t.Run("relative glob in the working directory", func(t *testing.T) {
		root := t.TempDir()
		if _, err := cautils.GetGitRootDir(root); err == nil {
			t.Skip("the temporary directory is inside a git checkout")
		}
		manifests, scan := globScanFixture(t, root)
		dir := viewOf(scan(manifests))
		assertReportedAt(t, dir, reporthandlingv2.Directory, manifests, "pod.yaml", "sub/pod.yaml")
		t.Chdir(manifests)
		glob := viewOf(scan("*.yaml"))
		assertReportedAt(t, glob, reporthandlingv2.Directory, manifests, "pod.yaml", "sub/pod.yaml")
		assert.Equal(t, dir, glob)
	})

	t.Run("inside a repository without commits", func(t *testing.T) {
		// Without a HEAD the scan is a directory scan anchored at the repository
		// root, which ScanRootPath finds by walking up from the input.
		root := t.TempDir()
		manifests, scan := globScanFixture(t, root)
		_, err := git.PlainInit(root, false)
		require.NoError(t, err)
		dir := viewOf(scan(manifests))
		assertReportedAt(t, dir, reporthandlingv2.Directory, root, "k8s/pod.yaml", "k8s/sub/pod.yaml")
		glob := viewOf(scan(filepath.Join(manifests, "*.yaml")))
		assertReportedAt(t, glob, reporthandlingv2.Directory, root, "k8s/pod.yaml", "k8s/sub/pod.yaml")
		assert.Equal(t, dir, glob)
	})

	t.Run("inside a committed repository", func(t *testing.T) {
		// Windows cannot open a path containing '*', so go-git only finds the
		// repository when the glob is resolved to its directory first.
		root := t.TempDir()
		manifests, scan := globScanFixture(t, root)
		repo, err := git.PlainInitWithOptions(root, &git.PlainInitOptions{InitOptions: git.InitOptions{DefaultBranch: plumbing.Master}})
		require.NoError(t, err)
		_, err = repo.CreateRemote(&gitconfig.RemoteConfig{Name: "origin", URLs: []string{"https://github.com/kubescape/kubescape"}})
		require.NoError(t, err)
		wt, err := repo.Worktree()
		require.NoError(t, err)
		require.NoError(t, wt.AddGlob("."))
		_, err = wt.Commit("fixture", &git.CommitOptions{Author: &object.Signature{Name: "kubescape", Email: "kubescape@example.com", When: time.Now()}})
		require.NoError(t, err)

		dir := viewOf(scan(manifests))
		assertReportedAt(t, dir, reporthandlingv2.GitLocal, root, "k8s/pod.yaml", "k8s/sub/pod.yaml")
		glob := viewOf(scan(filepath.Join(manifests, "*.yaml")))
		assertReportedAt(t, glob, reporthandlingv2.GitLocal, root, "k8s/pod.yaml", "k8s/sub/pod.yaml")
		assert.Equal(t, dir, glob)
	})
}
