package resourcehandler

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	gitv5 "github.com/go-git/go-git/v5"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Initializes a new instance of FileResourceHandler.
func TestNewFileResourceHandler_InitializesNewInstance(t *testing.T) {
	fileHandler := NewFileResourceHandler()
	assert.NotNil(t, fileHandler)
}

func drainFileResourceStream(batchChan <-chan *cautils.ResourceBatch, errChan <-chan error, setupErr error) ([]*cautils.ResourceBatch, []error) {
	var batches []*cautils.ResourceBatch
	if batchChan != nil {
		for batch := range batchChan {
			batches = append(batches, batch)
		}
	}

	var streamErrs []error
	if setupErr != nil {
		streamErrs = append(streamErrs, setupErr)
	}
	if errChan != nil {
		for streamErr := range errChan {
			streamErrs = append(streamErrs, streamErr)
		}
	}
	return batches, streamErrs
}

func TestFileResourceHandlerStreamResourcesBatchesPreCanceled(t *testing.T) {
	manifestPath := filepath.Join(t.TempDir(), "pod.yaml")
	require.NoError(t, os.WriteFile(manifestPath, []byte(singlePodManifest), 0o600))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	scanInfo := &cautils.ScanInfo{InputPatterns: []string{manifestPath}}
	session := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
	batchChan, errChan, _, err := NewFileResourceHandler().StreamResourcesBatches(ctx, session, scanInfo)
	batches, streamErrs := drainFileResourceStream(batchChan, errChan, err)

	assert.Empty(t, batches, "a pre-canceled stream must not emit a resource batch")
	assert.Nil(t, batchChan, "a setup error must not return a batch channel")
	assert.Nil(t, errChan, "a setup error must not return an error channel")
	require.Len(t, streamErrs, 1)
	assert.True(t, errors.Is(streamErrs[0], context.Canceled), "stream error = %v", streamErrs[0])
}

// cancelAfterEntryPreflightContext models cancellation immediately after the
// stream's entry preflight observes an active context. The post-collection
// preflight must observe the transition before the batch producer starts.
type cancelAfterEntryPreflightContext struct {
	context.Context
	cancel context.CancelFunc
	once   sync.Once
}

func (c *cancelAfterEntryPreflightContext) Err() error {
	err := c.Context.Err()
	c.once.Do(c.cancel)
	return err
}

func TestFileResourceHandlerStreamResourcesBatchesCanceledAfterEntryPreflight(t *testing.T) {
	manifestPath := filepath.Join(t.TempDir(), "pod.yaml")
	require.NoError(t, os.WriteFile(manifestPath, []byte(singlePodManifest), 0o600))

	baseCtx, cancel := context.WithCancel(context.Background())
	ctx := &cancelAfterEntryPreflightContext{Context: baseCtx, cancel: cancel}
	t.Cleanup(cancel)

	scanInfo := &cautils.ScanInfo{InputPatterns: []string{manifestPath}}
	session := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
	batchChan, errChan, _, err := NewFileResourceHandler().StreamResourcesBatches(ctx, session, scanInfo)
	batches, streamErrs := drainFileResourceStream(batchChan, errChan, err)

	assert.Empty(t, batches, "a stream canceled after entry preflight must not emit a resource batch")
	assert.Nil(t, batchChan, "a setup error must not return a batch channel")
	assert.Nil(t, errChan, "a setup error must not return an error channel")
	require.Len(t, streamErrs, 1)
	assert.True(t, errors.Is(streamErrs[0], context.Canceled), "stream error = %v", streamErrs[0])
}

func TestPublishFileResourceBatchPropagatesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	batchChan := make(chan *cautils.ResourceBatch, 1)
	errChan := make(chan error, 1)
	publishFileResourceBatch(ctx, batchChan, errChan, cautils.NewResourceBatch(cautils.ClusterScope))

	select {
	case batch := <-batchChan:
		t.Fatalf("canceled producer emitted batch: %#v", batch)
	default:
	}

	select {
	case err := <-errChan:
		assert.ErrorIs(t, err, context.Canceled)
	default:
		t.Fatal("canceled producer did not report an error")
	}
}

// This is deliberately a FileResourceHandler test rather than another parser
// count assertion: list items must survive manifest loading, offline resource
// resolution, and policy filtering before they become OPA input.
func TestFileResourceHandlerIndexesListEnvelopeItemsForPolicies(t *testing.T) {
	tests := []struct {
		name      string
		extension string
		manifest  string
		wantByGVR map[string]string
		wantNames map[string]string
	}{
		{
			name:      "JSON generic List",
			extension: "json",
			manifest: `{
  "apiVersion": "v1",
  "kind": "List",
  "items": [
    {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "listed-pod", "namespace": "default"}},
    {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "listed-service", "namespace": "default"}}
  ]
}`,
			wantByGVR: map[string]string{
				"/v1/pods":     "Pod",
				"/v1/services": "Service",
			},
			wantNames: map[string]string{
				"/v1/pods":     "listed-pod",
				"/v1/services": "listed-service",
			},
		},
		{
			name:      "JSON typed list",
			extension: "json",
			manifest: `{
  "apiVersion": "v1",
  "kind": "PodList",
  "items": [
    {"apiVersion": "v1", "metadata": {"name": "json-typed-pod", "namespace": "default"}}
  ]
}`,
			wantByGVR: map[string]string{"/v1/pods": "Pod"},
			wantNames: map[string]string{"/v1/pods": "json-typed-pod"},
		},
		{
			name:      "YAML typed list",
			extension: "yaml",
			manifest: `apiVersion: v1
kind: PodList
items:
  - kind: Pod
    metadata:
      name: yaml-typed-pod
      namespace: default
`,
			wantByGVR: map[string]string{"/v1/pods": "Pod"},
			wantNames: map[string]string{"/v1/pods": "yaml-typed-pod"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifestPath := filepath.Join(t.TempDir(), "resources."+tt.extension)
			require.NoError(t, os.WriteFile(manifestPath, []byte(tt.manifest), 0o600))

			match := reporthandling.RuleMatchObjects{
				APIGroups:   []string{""},
				APIVersions: []string{"v1"},
				Resources:   []string{"pods", "services"},
			}
			framework := *mockFramework("list-envelope-input", []reporthandling.Control{
				mockControl("list-envelope-input", []reporthandling.PolicyRule{
					mockRule("list-envelope-input", []reporthandling.RuleMatchObjects{match}, ""),
				}),
			})
			scanInfo := &cautils.ScanInfo{InputPatterns: []string{manifestPath}}
			session := cautils.NewOPASessionObj(
				context.Background(), []reporthandling.Framework{framework}, nil, scanInfo, nil,
			)

			resources, allResources, _, _, err := NewFileResourceHandler().GetResources(
				context.Background(), session, scanInfo,
			)
			require.NoError(t, err)
			require.Len(t, allResources, len(tt.wantByGVR))

			for gvr, wantKind := range tt.wantByGVR {
				require.Lenf(t, resources[gvr], 1, "expected %s in policy input %s", wantKind, gvr)
				resourceID := resources[gvr][0]
				resource, ok := allResources[resourceID]
				require.Truef(t, ok, "policy input %s referenced missing resource %s", gvr, resourceID)
				assert.Equal(t, wantKind, resource.GetKind())
				assert.Equal(t, "v1", resource.GetApiVersion())
				assert.Equal(t, tt.wantNames[gvr], resource.GetName())
			}
		})
	}
}

// A single-file scan must yield a repository-relative RelativePath: the SARIF and GitLab SAST printers build the finding's file location from it, and the GitLab printer drops findings whose path is empty, absolute, or escaping the repo root. See #2496.
func TestGetResourcesFromPath_SingleFileRelativePathIsRepositoryRelative(t *testing.T) {
	workloadIDToSource, workloads, err := getResourcesFromPath(context.TODO(), "../../cautils/testdata/mixed_extensions/pod.yaml", cautils.HelmValueOptions{})
	require.NoError(t, err)
	require.NotEmpty(t, workloads, "the single-file scan must discover the pod")

	for _, w := range workloads {
		src, ok := workloadIDToSource[w.GetID()]
		require.True(t, ok, "every workload must have a source")

		rel := src.RelativePath
		assert.NotEmpty(t, rel, "RelativePath must be set or the finding has no file to anchor to")
		assert.False(t, filepath.IsAbs(rel), "RelativePath must be repository-relative, not absolute: %q", rel)
		cleaned := filepath.ToSlash(filepath.Clean(rel))
		assert.False(t, cleaned == ".." || strings.HasPrefix(cleaned, "../"),
			"RelativePath must not escape the repository root: %q", rel)
		assert.Equal(t, "pod.yaml", filepath.Base(rel))
	}
}

// newRepoWithUnusableGitMetadata builds a repository that go-git can locate but
// NewLocalGitRepository rejects (unborn HEAD, no remotes), as a CI checkout often is,
// and writes manifestPath inside it.
func newRepoWithUnusableGitMetadata(t *testing.T, manifestPath string) string {
	t.Helper()

	repoRoot, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	_, err = gitv5.PlainInit(repoRoot, false)
	require.NoError(t, err)

	_, err = cautils.NewLocalGitRepository(repoRoot)
	require.Error(t, err, "the repository's git metadata must be unusable for this test to mean anything")

	absManifest := filepath.Join(repoRoot, filepath.FromSlash(manifestPath))
	require.NoError(t, os.MkdirAll(filepath.Dir(absManifest), 0o750))
	require.NoError(t, os.WriteFile(absManifest, []byte(singlePodManifest), 0o600))

	return repoRoot
}

// TestGetResourcesFromPath_AnchorsOnRepositoryRootWithoutUsableGitMetadata verifies
// that a scan reports paths relative to the repository root even when the
// repository's branch and remote metadata is unusable. A CI checkout with a detached
// HEAD or no configured remote is still a repository, and anchoring on the scan path
// instead drops the prefix, leaving GitLab and GitHub with findings that point at
// paths the repository does not contain.
func TestGetResourcesFromPath_AnchorsOnRepositoryRootWithoutUsableGitMetadata(t *testing.T) {
	const manifest = "workloads/apps/base/app/cronjobs.yaml"

	tests := []struct {
		name     string
		scanPath string
	}{
		{name: "directory scan", scanPath: "workloads"},
		{name: "single file scan", scanPath: manifest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repoRoot := newRepoWithUnusableGitMetadata(t, manifest)

			workloadIDToSource, workloads, err := getResourcesFromPath(context.TODO(), filepath.Join(repoRoot, filepath.FromSlash(tt.scanPath)), cautils.HelmValueOptions{})
			require.NoError(t, err)
			require.NotEmpty(t, workloads)

			for _, w := range workloads {
				src, ok := workloadIDToSource[w.GetID()]
				require.True(t, ok, "every workload must have a source")
				assert.Equal(t, manifest, filepath.ToSlash(src.RelativePath), "the path must be relative to the repository root, not the scan path")
				assert.Equal(t, repoRoot, src.Path, "Source.Path must be the root RelativePath resolves against")
			}
		})
	}
}

const singlePodManifest = `apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: nginx
    image: nginx:1.14.2
`

// A chart whose helm render fails must still have its static templates plain-scanned. The render is
// best-effort and drops the whole chart on any template error, so excluding templates/ unconditionally
// would make those resources reach neither loader and vanish silently. Regression guard for the #2501
// review: templates/ is excluded only for charts that rendered without errors.
func TestGetResourcesFromPath_ScansTemplatesOfChartThatFailedToRender(t *testing.T) {
	_, workloads, err := getResourcesFromPath(context.TODO(), "../../cautils/testdata/helm_chart_broken", cautils.HelmValueOptions{})
	require.NoError(t, err)

	var found bool
	for _, w := range workloads {
		if w.GetKind() == "ServiceAccount" && w.GetName() == "important-sa" {
			found = true
		}
	}
	assert.True(t, found, "a static template of a chart that failed to render must still be scanned")
}

func createMockGitRepo(t *testing.T, hasOrigin bool) string {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	require.NoError(t, os.MkdirAll(filepath.Join(gitDir, "refs", "heads"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/master\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(gitDir, "refs", "heads", "master"), []byte("0000000000000000000000000000000000000000\n"), 0o600))

	configContent := `[core]
	repositoryformatversion = 0
[remote "upstream"]
	url = https://example.com/upstream.git
`
	if hasOrigin {
		configContent += `[remote "origin"]
	url = https://example.com/origin.git
`
	}
	require.NoError(t, os.WriteFile(filepath.Join(gitDir, "config"), []byte(configContent), 0o600))
	return dir
}

func TestResolveHelmRemotePath(t *testing.T) {
	healthyRepo := createMockGitRepo(t, true)
	gitHealthy, err := cautils.NewLocalGitRepository(healthyRepo)
	require.NoError(t, err)

	brokenRepo := createMockGitRepo(t, false)
	gitBroken, err := cautils.NewLocalGitRepository(brokenRepo)
	require.NoError(t, err)

	tests := []struct {
		name       string
		clonedRepo string
		gitRepo    *cautils.LocalGitRepository
		want       string
	}{
		{
			name:       "empty clonedRepo",
			clonedRepo: "",
			gitRepo:    gitHealthy,
			want:       "",
		},
		{
			name:       "nil gitRepo",
			clonedRepo: "some-repo",
			gitRepo:    nil,
			want:       "",
		},
		{
			name:       "repo whose remote lookup fails",
			clonedRepo: "some-repo",
			gitRepo:    gitBroken,
			want:       "",
		},
		{
			name:       "healthy repo",
			clonedRepo: "some-repo",
			gitRepo:    gitHealthy,
			want:       "https://example.com/origin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveHelmRemotePath(tt.clonedRepo, tt.gitRepo)
			assert.Equal(t, tt.want, got)
		})
	}
}

// A chart that renders cleanly has its templates covered by the render, so the plain-YAML loader must
// not scan them again (no duplicate, no malformed-template warnings), while crds/ and files outside
// templates/ stay plainly scanned.
func TestGetResourcesFromPath_RenderedChartTemplatesLoadedOnce(t *testing.T) {
	_, workloads, err := getResourcesFromPath(context.TODO(), "../../cautils/testdata/helm_chart_layout", cautils.HelmValueOptions{})
	require.NoError(t, err)

	counts := map[string]int{}
	for _, w := range workloads {
		counts[w.GetKind()+"/"+w.GetName()]++
	}

	// rendered exactly once by helm, never re-scanned as a raw template
	assert.Equal(t, 1, counts["ServiceAccount/mychart-static"], "static template must be loaded once, by the render")
	assert.Equal(t, 1, counts["Deployment/-mychart"], "templated deployment must come from the render")
	assert.Equal(t, 1, counts["Service/-mysubchart"], "subchart template must come from the render")
	// not rendered by helm, so still plainly scanned
	assert.Equal(t, 1, counts["CustomResourceDefinition/widgets.example.com"], "crds/ must stay plainly scanned")
	assert.Equal(t, 1, counts["Pod/plain-outside-chart"], "files outside the chart must stay plainly scanned")
}

// Deduplicates resources discovered by both kustomize render and the plain-YAML glob.
func TestGetResourcesFromPath_DeduplicatesKustomizeAndPlainYaml(t *testing.T) {
	workloadIDToSource, workloads, err := getResourcesFromPath(context.TODO(), "../../cautils/testdata/kustomize/base", cautils.HelmValueOptions{})
	require.NoError(t, err)

	var deployments []string
	for _, w := range workloads {
		if w.GetKind() == "Deployment" {
			deployments = append(deployments, w.GetID())
		}
	}

	require.Len(t, deployments, 1)
	assert.Equal(t, reporthandling.SourceTypeKustomizeDirectory, workloadIDToSource[deployments[0]].FileType)
}

// Kustomize transformers mutate identity fields, so path-based exclusion (not identity dedup) must keep the result single.
func TestGetResourcesFromPath_KustomizeTransformersDoNotDuplicate(t *testing.T) {
	workloadIDToSource, workloads, err := getResourcesFromPath(context.TODO(), "../../cautils/testdata/kustomize/transformed", cautils.HelmValueOptions{})
	require.NoError(t, err)

	var deploymentIDs []string
	var deployment workloadinterface.IMetadata
	for _, w := range workloads {
		if w.GetKind() == "Deployment" {
			deploymentIDs = append(deploymentIDs, w.GetID())
			deployment = w
		}
	}

	require.Len(t, deploymentIDs, 1)
	assert.Equal(t, reporthandling.SourceTypeKustomizeDirectory, workloadIDToSource[deploymentIDs[0]].FileType)
	assert.Equal(t, "production", deployment.GetNamespace())
	assert.Equal(t, "prod-test-app", deployment.GetName())
}

func TestGetResourcesFromPath_KustomizeOwnsReferencedHelmChart(t *testing.T) {
	installFakeHelm(t)

	root := t.TempDir()
	chartDir := filepath.Join(root, "vendor", "charts", "app")
	templateDir := filepath.Join(chartDir, "templates")
	require.NoError(t, os.MkdirAll(templateDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(root, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namePrefix: prod-
helmGlobals:
  chartHome: vendor/charts
helmCharts:
  - name: app
    releaseName: first
  - name: app
    releaseName: second
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: app\nversion: 0.1.0\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "values.yaml"), []byte("{}\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(templateDir, "configmap.yaml"), []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Release.Name }}
`), 0o600))

	sources, workloads, err := getResourcesFromPath(context.Background(), root, cautils.HelmValueOptions{})
	require.NoError(t, err)

	counts := map[string]int{}
	var configMaps int
	for _, workload := range workloads {
		counts[workload.GetKind()+"/"+workload.GetName()]++
		if workload.GetKind() == "ConfigMap" {
			configMaps++
			assert.Equal(t, reporthandling.SourceTypeKustomizeDirectory, sources[workload.GetID()].FileType)
		}
	}
	assert.Equal(t, 1, counts["ConfigMap/prod-first"], "the first Kustomize inflation must survive")
	assert.Equal(t, 1, counts["ConfigMap/prod-second"], "the second Kustomize inflation must survive")
	assert.Equal(t, 2, configMaps, "the chart must not also be rendered as a standalone Helm release")
}

func installFakeHelm(t *testing.T) {
	t.Helper()
	if os.PathSeparator == '\\' {
		t.Skip("the deterministic Helm test double requires a POSIX shell")
	}

	binDir := t.TempDir()
	helmPath := filepath.Join(binDir, "helm")
	//nolint:gosec // The test-owned Helm double must be executable by Kustomize.
	require.NoError(t, os.WriteFile(helmPath, []byte(`#!/bin/sh
set -eu
die() {
    printf '%s\n' "$*" >&2
    exit 2
}
case "${1:-}" in
version)
    [ "$#" -eq 3 ] && [ "$2" = "-c" ] && [ "$3" = "--short" ] || die "unexpected version args: $*"
    printf '%s\n' 'v3.14.0+gtest'
    ;;
template)
	[ "$#" -ge 3 ] || die "missing template args"
	release_name=$2
	chart_path=$3
	[ -f "$chart_path/Chart.yaml" ] && [ -f "$chart_path/templates/configmap.yaml" ] || die "unexpected chart: $chart_path"
	printf 'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: %s\n' "$release_name"
    ;;
*)
	die "unsupported helm command: ${1:-}"
    ;;
esac
`), 0o750))
	t.Setenv("PATH", binDir)
}

func TestGetResourcesFromPathRejectsDirectoryWithoutKubernetesResources(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "values.yaml"), []byte("replicas: 3\n"), 0o600))

	sources, workloads, err := getResourcesFromPath(context.Background(), dir, cautils.HelmValueOptions{})

	require.Error(t, err)
	assert.Nil(t, sources)
	assert.Nil(t, workloads)
	assert.Contains(t, err.Error(), "no scannable Kubernetes resources")
}

func TestGetResourcesFromPathPropagatesKustomizeFailure(t *testing.T) {
	dir := t.TempDir()
	kustomization := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - missing.yaml
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte(kustomization), 0o600))

	sources, workloads, err := getResourcesFromPath(context.Background(), dir, cautils.HelmValueOptions{})

	require.Error(t, err)
	assert.Nil(t, sources)
	assert.Nil(t, workloads)
	assert.Contains(t, err.Error(), "failed to render Kustomize resources")
}

func TestGetResourcesFromPath_RendersNestedKustomizeDirectory(t *testing.T) {
	repoRoot := t.TempDir()
	appDir := filepath.Join(repoRoot, "app")
	require.NoError(t, os.MkdirAll(appDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(appDir, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namePrefix: prod-
resources:
  - deployment.yaml
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(appDir, "deployment.yaml"), []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  selector:
    matchLabels:
      app: app
  template:
    metadata:
      labels:
        app: app
    spec:
      containers:
        - name: app
          image: nginx:1.27
`), 0o600))

	_, workloads, err := getResourcesFromPath(context.Background(), repoRoot, cautils.HelmValueOptions{})
	require.NoError(t, err)

	counts := map[string]int{}
	for _, workload := range workloads {
		counts[workload.GetKind()+"/"+workload.GetName()]++
	}
	assert.Equal(t, 1, counts["Deployment/prod-app"], "the nested Kustomization's transformed output must be scanned")
	assert.Zero(t, counts["Deployment/app"], "the untransformed raw manifest must not also be scanned")
	assert.Zero(t, counts["Kustomization/"], "the Kustomization document itself must not enter the scanned set")
}

func TestGetResourcesFromPath_NestedKustomizeSiblingFilesStillScanned(t *testing.T) {
	repoRoot := t.TempDir()
	appDir := filepath.Join(repoRoot, "app")
	require.NoError(t, os.MkdirAll(appDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(appDir, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namePrefix: prod-
resources:
  - deployment.yaml
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(appDir, "deployment.yaml"), []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  selector:
    matchLabels:
      app: app
  template:
    metadata:
      labels:
        app: app
    spec:
      containers:
        - name: app
          image: nginx:1.27
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(repoRoot, "standalone.yaml"), []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: standalone
`), 0o600))

	_, workloads, err := getResourcesFromPath(context.Background(), repoRoot, cautils.HelmValueOptions{})
	require.NoError(t, err)

	counts := map[string]int{}
	for _, workload := range workloads {
		counts[workload.GetKind()+"/"+workload.GetName()]++
	}
	assert.Equal(t, 1, counts["Deployment/prod-app"])
	assert.Equal(t, 1, counts["ConfigMap/standalone"], "a manifest outside the Kustomize directory must still be scanned")
}

// TestExcludeFilesUnderDirectories asserts that only sources inside the given
// directories are dropped: siblings that merely share an ancestor, or unrelated
// files, survive. The containment check is directory-aware, so a root located
// just above the scan tree must not swallow unrelated inputs.
func TestExcludeFilesUnderDirectories(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	nestedDir := filepath.Join(appDir, "config", "base")
	require.NoError(t, os.MkdirAll(nestedDir, 0o750))

	sources := map[string][]workloadinterface.IMetadata{
		filepath.Join(nestedDir, "deployment.yaml"):    {localWorkloadWithPath("apps/v1", "Deployment", "", "app", filepath.Join(nestedDir, "deployment.yaml"))},
		filepath.Join(appDir, "service.yaml"):          {localWorkloadWithPath("v1", "Service", "", "app", filepath.Join(appDir, "service.yaml"))},
		filepath.Join(root, "app-docs", "policy.yaml"): {localWorkloadWithPath("v1", "Pod", "default", "docs", filepath.Join(root, "app-docs", "policy.yaml"))},
		filepath.Join(root, "standalone.yaml"):         {localWorkloadWithPath("v1", "ConfigMap", "default", "standalone", filepath.Join(root, "standalone.yaml"))},
	}

	excludeFilesUnderDirectories(sources, []string{appDir})

	assert.NotContains(t, sources, filepath.Join(nestedDir, "deployment.yaml"), "a file nested below the directory must be excluded")
	assert.NotContains(t, sources, filepath.Join(appDir, "service.yaml"), "a file directly inside the directory must be excluded")
	assert.Contains(t, sources, filepath.Join(root, "app-docs", "policy.yaml"), "a sibling sharing a name prefix must survive")
	assert.Contains(t, sources, filepath.Join(root, "standalone.yaml"), "an unrelated file must survive")
}

// TestExcludeFilesUnderDirectories_RootDirectory asserts that a directory at the
// filesystem root matches through the canonical relative-path comparison, where
// the old string-prefix approach mangled the joined separator (#2889).
func TestExcludeFilesUnderDirectories_RootDirectory(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "deployment.yaml")
	sources := map[string][]workloadinterface.IMetadata{
		source: {localWorkloadWithPath("apps/v1", "Deployment", "", "app", source)},
	}

	excludeFilesUnderDirectories(sources, []string{string(filepath.Separator)})

	assert.NotContains(t, sources, source, "every absolute path lives under the root directory")
}

// TestExcludeFilesUnderDirectories_CanonicalizesSymlinkedDirs asserts that a Kustomize
// directory discovered under a symlinked scan path still excludes its inputs, which are
// reported with the symlinked (lexical) prefix while the directory is reported physically.
// The old string-prefix comparison could not see the match across the link (#2889).
func TestExcludeFilesUnderDirectories_CanonicalizesSymlinkedDirs(t *testing.T) {
	realParent := t.TempDir()
	physicalApp := filepath.Join(realParent, "app")
	source := filepath.Join(physicalApp, "deployment.yaml")
	require.NoError(t, os.MkdirAll(physicalApp, 0o750))
	require.NoError(t, os.WriteFile(source, []byte(singlePodManifest), 0o600))

	linkedParent := filepath.Join(t.TempDir(), "linked-parent")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	lexicalSource := filepath.Join(linkedParent, "app", "deployment.yaml")

	sources := map[string][]workloadinterface.IMetadata{
		lexicalSource: {localWorkloadWithPath("apps/v1", "Deployment", "", "app", lexicalSource)},
	}

	excludeFilesUnderDirectories(sources, []string{physicalApp})

	assert.NotContains(t, sources, lexicalSource, "the input is under the physical directory, so it must be excluded")
}
