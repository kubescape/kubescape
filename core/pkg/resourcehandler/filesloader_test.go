package resourcehandler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"

	gitv5 "github.com/go-git/go-git/v5"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/pathcontainment"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	helmchart "helm.sh/helm/v3/pkg/chart"
	helmchartutil "helm.sh/helm/v3/pkg/chartutil"
)

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
	workloadIDToSource, workloads, _, err := getResourcesFromPath(context.TODO(), "../../cautils/testdata/mixed_extensions/pod.yaml", cautils.HelmValueOptions{}, nil)
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

// Outside a git repository the scanned file itself was taken as the root for
// every file type but YAML, so a single JSON or Terraform file got the relative
// path "." and lost its source. SARIF and GitLab SAST drop results without a
// source, and fix cannot find the file.
func TestGetResourcesFromPath_SingleFileOutsideRepositoryKeepsItsSource(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		contents string
		fileType string
	}{
		{
			name:     "yaml",
			file:     "pod.yaml",
			contents: "apiVersion: v1\nkind: Pod\nmetadata:\n  name: pod\nspec:\n  containers:\n    - name: app\n      image: nginx\n",
			fileType: reporthandling.SourceTypeYaml,
		},
		{
			name:     "json",
			file:     "pod.json",
			contents: `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod"},"spec":{"containers":[{"name":"app","image":"nginx"}]}}`,
			fileType: reporthandling.SourceTypeJson,
		},
		{
			name:     "terraform",
			file:     "main.tf",
			contents: terraformPodFixture,
			fileType: "Terraform",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			// Inside a checkout the root is the repository root instead.
			if _, err := cautils.GetGitRootDir(dir); err == nil {
				t.Skip("the temporary directory is inside a git checkout")
			}
			path := filepath.Join(dir, tt.file)
			require.NoError(t, os.WriteFile(path, []byte(tt.contents), 0o600))

			workloadIDToSource, workloads, _, err := getResourcesFromPath(context.Background(), path, cautils.HelmValueOptions{}, nil)
			require.NoError(t, err)
			require.Len(t, workloads, 1)

			src, ok := workloadIDToSource[workloads[0].GetID()]
			require.True(t, ok, "the workload must have a source")
			assert.Equal(t, dir, src.Path)
			assert.Equal(t, tt.file, src.RelativePath)
			assert.Equal(t, tt.fileType, src.FileType)
		})
	}
}

func TestGetResourcesFromPath_SingleManifestDoesNotRenderUnrelatedKustomizeDirectory(t *testing.T) {
	root := t.TempDir()
	manifestPath := filepath.Join(root, "manifest.yaml")
	require.NoError(t, os.WriteFile(manifestPath, []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: requested
`), 0o600))

	// listDirs treats a file path as a basename pattern below its parent. A
	// Kustomize directory with that basename makes the unintended traversal
	// observable instead of relying on implementation details alone.
	unrelatedDirectory := filepath.Join(root, "unrelated", "manifest.yaml")
	require.NoError(t, os.MkdirAll(unrelatedDirectory, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(unrelatedDirectory, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namePrefix: unrelated-
resources:
  - deployment.yaml
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(unrelatedDirectory, "deployment.yaml"), []byte(`apiVersion: apps/v1
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

	_, workloads, _, err := getResourcesFromPath(context.Background(), manifestPath, cautils.HelmValueOptions{}, nil)
	require.NoError(t, err)
	require.Len(t, workloads, 1, "an exact file scan must not add resources from its parent tree")
	assert.Equal(t, "ConfigMap", workloads[0].GetKind())
	assert.Equal(t, "requested", workloads[0].GetName())
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

			workloadIDToSource, workloads, _, err := getResourcesFromPath(context.TODO(), filepath.Join(repoRoot, filepath.FromSlash(tt.scanPath)), cautils.HelmValueOptions{}, nil)
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
func TestGetResourcesFromPath_FailsWhenScannedChartFailsToRender(t *testing.T) {
	_, _, _, err := getResourcesFromPath(context.TODO(), "../../cautils/testdata/helm_chart_broken/brokenchart", cautils.HelmValueOptions{}, nil)
	require.ErrorIs(t, err, cautils.ErrHelmRenderFailed)
	assert.Contains(t, err.Error(), "brokenchart")
}

// A chart Helm cannot load is never rendered. When it is the scanned input, the
// scan fails with the cause rather than as an input with no resources.
func TestGetResourcesFromPath_FailsWhenScannedChartFailsToLoad(t *testing.T) {
	chartDir := filepath.Join(t.TempDir(), "chart")
	require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "templates"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: unloadable\nversion: 0.1.0\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "values.yaml"), []byte("- a\n- b\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "templates", "sa.yaml"), []byte("apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: sa\n"), 0o600))

	_, _, _, err := getResourcesFromPath(context.TODO(), chartDir, cautils.HelmValueOptions{}, nil)

	require.ErrorIs(t, err, cautils.ErrHelmLoadFailed)
	assert.NotErrorIs(t, err, cautils.ErrNoManifestFiles)
	assert.Contains(t, err.Error(), "values.yaml", "the cause is in the error, not only in a warning")
}

func TestGetResourcesFromPath_SkipsTemplatesOfNestedChartThatFailedToLoad(t *testing.T) {
	dir := t.TempDir()
	chartDir := filepath.Join(dir, "chart")
	require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "templates"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: unloadable\nversion: 0.1.0\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "values.yaml"), []byte("- a\n- b\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "templates", "sa.yaml"), []byte("apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: sa\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pod.yaml"), []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: plain\nspec:\n  containers:\n    - name: c\n      image: nginx\n"), 0o600))

	_, workloads, skips, err := getResourcesFromPath(context.TODO(), dir, cautils.HelmValueOptions{}, nil)
	require.NoError(t, err, "a broken chart inside a broader scan must not fail the scan")

	names := make([]string, 0, len(workloads))
	for _, w := range workloads {
		names = append(names, w.GetName())
	}
	assert.Equal(t, []string{"plain"}, names, "templates of a chart that failed to load must not be scanned as plain YAML")
	require.Len(t, skips, 1)
	assert.Equal(t, "unrendered Helm template: its chart was not rendered", skips[0].Reason)
}

func TestGetResourcesFromPath_SkipsTemplatesOfNestedChartThatFailedToRender(t *testing.T) {
	dir := t.TempDir()
	chartDir := filepath.Join(dir, "chart")
	require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "templates"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: broken\nversion: 0.1.0\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "templates", "sa.yaml"), []byte(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ required "name is required" .Values.name }}
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "templates", "static.yaml"), []byte("apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: static-sa\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pod.yaml"), []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: plain\nspec:\n  containers:\n    - name: c\n      image: nginx\n"), 0o600))

	_, workloads, skips, err := getResourcesFromPath(context.TODO(), dir, cautils.HelmValueOptions{}, nil)
	require.NoError(t, err, "a broken chart inside a broader scan must not fail the scan")

	names := make([]string, 0, len(workloads))
	for _, w := range workloads {
		names = append(names, w.GetName())
	}
	assert.Equal(t, []string{"plain"}, names, "templates of a chart that failed to render must not be scanned as plain YAML")
	require.Len(t, skips, 2)
	for _, skip := range skips {
		assert.Equal(t, "unrendered Helm template: its chart was not rendered", skip.Reason)
	}
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
	_, workloads, _, err := getResourcesFromPath(context.TODO(), "../../cautils/testdata/helm_chart_layout", cautils.HelmValueOptions{}, nil)
	require.NoError(t, err)

	counts := map[string]int{}
	for _, w := range workloads {
		counts[w.GetKind()+"/"+w.GetName()]++
	}

	// rendered exactly once by helm, never re-scanned as a raw template
	assert.Equal(t, 1, counts["ServiceAccount/mychart-static"], "static template must be loaded once, by the render")
	assert.Equal(t, 1, counts["Deployment/release-name-mychart"], "templated deployment must come from the render")
	assert.Equal(t, 1, counts["Service/release-name-mysubchart"], "subchart template must come from the render")
	// not rendered by helm, so still plainly scanned
	assert.Equal(t, 1, counts["CustomResourceDefinition/widgets.example.com"], "crds/ must stay plainly scanned")
	assert.Equal(t, 1, counts["Pod/plain-outside-chart"], "files outside the chart must stay plainly scanned")
}

// Deduplicates resources discovered by both kustomize render and the plain-YAML glob.
func TestGetResourcesFromPath_DeduplicatesKustomizeAndPlainYaml(t *testing.T) {
	workloadIDToSource, workloads, _, err := getResourcesFromPath(context.TODO(), "../../cautils/testdata/kustomize/base", cautils.HelmValueOptions{}, nil)
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
	workloadIDToSource, workloads, _, err := getResourcesFromPath(context.TODO(), "../../cautils/testdata/kustomize/transformed", cautils.HelmValueOptions{}, nil)
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

	sources, workloads, _, err := getResourcesFromPath(context.Background(), root, cautils.HelmValueOptions{}, nil)
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
    printf '%s\n' 'v3.14.0+gtest'
    ;;
template)
	[ "$#" -ge 3 ] || die "missing template args"
	release_name=$2
	chart_path=$3
	[ -f "$chart_path/Chart.yaml" ] && [ -f "$chart_path/templates/configmap.yaml" ] || die "unexpected chart: $chart_path"
	printf 'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: %s\n' "$release_name"
	include_crds=false
	for arg in "$@"; do
		if [ "$arg" = "--include-crds" ]; then
			include_crds=true
		fi
	done
	if [ "$include_crds" = true ] && [ -f "$chart_path/crds/test.yaml" ]; then
		printf '%s\n' '---'
		while IFS= read -r line || [ -n "$line" ]; do
			printf '%s\n' "$line"
		done < "$chart_path/crds/test.yaml"
	fi
    ;;
*)
	die "unsupported helm command: ${1:-}"
    ;;
esac
`), 0o750))
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestGetResourcesFromPath_RendersNestedKustomizeDirectoryWithPreciseOwnership(t *testing.T) {
	repoRoot := t.TempDir()
	appDir := filepath.Join(repoRoot, "app")
	sharedDir := filepath.Join(repoRoot, "shared")
	require.NoError(t, os.MkdirAll(appDir, 0o750))
	require.NoError(t, os.MkdirAll(sharedDir, 0o750))
	// External resources must be referenced through a base directory with its
	// own Kustomization, rather than loading an individual file outside appDir.
	require.NoError(t, os.WriteFile(filepath.Join(sharedDir, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namePrefix: base-
resources:
  - shared.yaml
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(appDir, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namePrefix: prod-
resources:
  - deployment.yaml
  - ../shared
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
	require.NoError(t, os.WriteFile(filepath.Join(sharedDir, "shared.yaml"), []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: shared
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(appDir, "unreferenced.yaml"), []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: unreferenced
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(repoRoot, "standalone.yaml"), []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: standalone
`), 0o600))

	sources, workloads, _, err := getResourcesFromPath(context.Background(), repoRoot, cautils.HelmValueOptions{}, nil)
	require.NoError(t, err)

	counts := map[string]int{}
	var renderedDeployment, renderedShared workloadinterface.IMetadata
	for _, workload := range workloads {
		counts[workload.GetKind()+"/"+workload.GetName()]++
		if workload.GetKind() == "Deployment" && workload.GetName() == "prod-app" {
			renderedDeployment = workload
		}
		if workload.GetKind() == "ConfigMap" && workload.GetName() == "prod-base-shared" {
			renderedShared = workload
		}
	}

	assert.Equal(t, 1, counts["Deployment/prod-app"], "the nested Kustomize output must be scanned")
	assert.Zero(t, counts["Deployment/app"], "the untransformed source manifest must not also be scanned")
	assert.Equal(t, 1, counts["ConfigMap/prod-base-shared"], "a referenced base outside the Kustomize directory must be included in the render")
	assert.Equal(t, 1, counts["ConfigMap/base-shared"], "the sibling base is also independently discovered during a broad scan")
	assert.Zero(t, counts["ConfigMap/shared"], "the external source must not also be scanned raw")
	assert.Zero(t, counts["Kustomization/"], "the Kustomization file is build input, not a workload")
	assert.Equal(t, 1, counts["ConfigMap/unreferenced"], "an unreferenced manifest beside the Kustomization must remain")
	assert.Equal(t, 1, counts["ConfigMap/standalone"], "plain manifests outside the Kustomize tree must remain")

	require.NotNil(t, renderedDeployment)
	source, ok := sources[renderedDeployment.GetID()]
	require.True(t, ok)
	assert.Equal(t, reporthandling.SourceTypeKustomizeDirectory, source.FileType)
	assert.Equal(t, "app/deployment.yaml", filepath.ToSlash(source.RelativePath),
		"a rendered resource is attributed to the file Kustomize read it from, not only to the directory")
	assert.Equal(t, appDir, source.KustomizeDirectoryName, "the directory is still recorded")

	require.NotNil(t, renderedShared)
	sharedSource, ok := sources[renderedShared.GetID()]
	require.True(t, ok)
	assert.Equal(t, "shared/shared.yaml", filepath.ToSlash(sharedSource.RelativePath),
		"a source outside the Kustomize directory is attributed to that file")
	assert.Equal(t, appDir, sharedSource.KustomizeDirectoryName)
}

func TestGetResourcesFromPath_NestedKustomizeOwnsReferencedHelmChart(t *testing.T) {
	installFakeHelm(t)

	repoRoot := t.TempDir()
	appDir := filepath.Join(repoRoot, "app")
	ownedChart := filepath.Join(appDir, "charts", "app")
	standaloneChart := filepath.Join(repoRoot, "standalone-chart")

	writeChart := func(directory, name string) {
		t.Helper()
		require.NoError(t, os.MkdirAll(filepath.Join(directory, "templates"), 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(directory, "Chart.yaml"), []byte("apiVersion: v2\nname: "+name+"\nversion: 0.1.0\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(directory, "values.yaml"), []byte("{}\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(directory, "templates", "configmap.yaml"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: "+name+"\n"), 0o600))
	}
	writeChart(ownedChart, "app")
	writeChart(standaloneChart, "standalone")
	require.NoError(t, os.WriteFile(filepath.Join(appDir, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namePrefix: prod-
helmCharts:
  - name: app
    releaseName: app
`), 0o600))

	sources, workloads, _, err := getResourcesFromPath(context.Background(), repoRoot, cautils.HelmValueOptions{}, nil)
	require.NoError(t, err)

	counts := map[string]int{}
	var transformed workloadinterface.IMetadata
	var standalone workloadinterface.IMetadata
	for _, workload := range workloads {
		counts[workload.GetKind()+"/"+workload.GetName()]++
		switch workload.GetName() {
		case "prod-app":
			transformed = workload
		case "standalone":
			standalone = workload
		}
	}
	assert.Equal(t, 1, counts["ConfigMap/prod-app"], "the nested Kustomize Helm output must be scanned exactly once")
	assert.Zero(t, counts["ConfigMap/app"], "the Kustomize-owned chart must not also be rendered as a standalone release")
	assert.Equal(t, 1, counts["ConfigMap/standalone"], "an unreferenced sibling chart must remain in generic Helm discovery")
	require.NotNil(t, transformed)
	require.NotNil(t, standalone)
	assert.Equal(t, reporthandling.SourceTypeKustomizeDirectory, sources[transformed.GetID()].FileType)
	assert.Equal(t, reporthandling.SourceTypeHelmChart, sources[standalone.GetID()].FileType)
}

func TestGetResourcesFromPath_NestedKustomizeHelmCRDOwnershipFollowsIncludeCRDs(t *testing.T) {
	for _, includeCRDs := range []bool{false, true} {
		t.Run(fmt.Sprintf("includeCRDs=%t", includeCRDs), func(t *testing.T) {
			installFakeHelm(t)

			repoRoot := t.TempDir()
			appDir := filepath.Join(repoRoot, "app")
			chartDir := filepath.Join(appDir, "vendor", "charts", "app")
			require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "templates"), 0o750))
			require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "crds"), 0o750))
			require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: app\nversion: 0.1.0\n"), 0o600))
			require.NoError(t, os.WriteFile(filepath.Join(chartDir, "values.yaml"), []byte("{}\n"), 0o600))
			require.NoError(t, os.WriteFile(filepath.Join(chartDir, "templates", "configmap.yaml"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app\n"), 0o600))
			require.NoError(t, os.WriteFile(filepath.Join(chartDir, "crds", "test.yaml"), []byte(`apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: widgets.example.com
spec:
  group: example.com
  names:
    kind: Widget
    plural: widgets
  scope: Namespaced
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
`), 0o600))
			require.NoError(t, os.MkdirAll(appDir, 0o750))
			require.NoError(t, os.WriteFile(filepath.Join(appDir, "kustomization.yaml"), []byte(fmt.Sprintf(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
helmGlobals:
  chartHome: vendor/charts
helmCharts:
  - name: app
    releaseName: app
    includeCRDs: %t
`, includeCRDs)), 0o600))

			ctx := context.Background()
			kustomizeResult, err := cautils.LoadResourcesFromKustomizeDirectories(ctx, repoRoot)
			require.NoError(t, err)
			var renderedCRDs int
			for _, renderedWorkloads := range kustomizeResult.SourceToWorkloads {
				for _, workload := range renderedWorkloads {
					if workload.GetKind() == "CustomResourceDefinition" && workload.GetName() == "widgets.example.com" {
						renderedCRDs++
					}
				}
			}

			rawSources, _, err := cautils.LoadResourcesFromFiles(ctx, repoRoot, repoRoot, kustomizeResult.OwnedHelmChartDirectories)
			require.NoError(t, err)
			var rawCRDs int
			for source, rawWorkloads := range rawSources {
				if kustomizeResult.OwnsPlainFile(source) {
					continue
				}
				for _, workload := range rawWorkloads {
					if workload.GetKind() == "CustomResourceDefinition" && workload.GetName() == "widgets.example.com" {
						rawCRDs++
					}
				}
			}
			if includeCRDs {
				assert.Equal(t, 1, renderedCRDs, "Kustomize must emit the CRD when includeCRDs is true")
				assert.Zero(t, rawCRDs, "the raw pass must exclude the CRD before identity deduplication")
			} else {
				assert.Zero(t, renderedCRDs, "Kustomize must omit the CRD when includeCRDs is false")
				assert.Equal(t, 1, rawCRDs, "the raw pass must retain the omitted CRD")
			}

			sources, workloads, _, err := getResourcesFromPath(ctx, repoRoot, cautils.HelmValueOptions{}, nil)
			require.NoError(t, err)

			var crds []workloadinterface.IMetadata
			for _, workload := range workloads {
				if workload.GetKind() == "CustomResourceDefinition" && workload.GetName() == "widgets.example.com" {
					crds = append(crds, workload)
				}
			}
			require.Len(t, crds, 1, "the final CRD must be present exactly once")
			expectedSourceType := reporthandling.SourceTypeYaml
			if includeCRDs {
				expectedSourceType = reporthandling.SourceTypeKustomizeDirectory
			}
			assert.Equal(t, expectedSourceType, sources[crds[0].GetID()].FileType)
		})
	}
}

func TestGetResourcesFromPath_BrokenNestedKustomizeDoesNotAbortBroadScan(t *testing.T) {
	repoRoot := t.TempDir()
	brokenDir := filepath.Join(repoRoot, "broken")
	require.NoError(t, os.MkdirAll(brokenDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(brokenDir, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - valid.yaml
  - missing.yaml
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(brokenDir, "valid.yaml"), []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: inside-broken
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(repoRoot, "standalone.yaml"), []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: standalone
`), 0o600))

	sources, workloads, _, err := getResourcesFromPath(context.Background(), repoRoot, cautils.HelmValueOptions{}, nil)
	require.NoError(t, err)

	counts := map[string]int{}
	var insideBroken workloadinterface.IMetadata
	for _, workload := range workloads {
		counts[workload.GetKind()+"/"+workload.GetName()]++
		if workload.GetKind() == "ConfigMap" && workload.GetName() == "inside-broken" {
			insideBroken = workload
		}
	}
	assert.Equal(t, 1, counts["ConfigMap/standalone"], "an invalid child configuration must not hide valid sibling resources")
	assert.Equal(t, 1, counts["ConfigMap/inside-broken"], "a valid input in the failed build must remain in the raw fallback")
	require.NotNil(t, insideBroken)
	assert.Equal(t, reporthandling.SourceTypeYaml, sources[insideBroken.GetID()].FileType)
}

func TestGetResourcesFromPathRejectsDirectoryWithoutKubernetesResources(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "values.yaml"), []byte("replicas: 3\n"), 0o600))

	sources, workloads, skips, err := getResourcesFromPath(context.Background(), dir, cautils.HelmValueOptions{}, nil)

	require.Error(t, err)
	assert.Nil(t, sources)
	assert.Nil(t, workloads)
	assert.Empty(t, skips)
	assert.Contains(t, err.Error(), "no scannable Kubernetes resources")
}

func TestGetResourcesFromPathWithInvalidManifest(t *testing.T) {
	cases := []struct {
		name     string
		prepare  func(t *testing.T, dir string) string
		manifest string
		content  string
		kind     string
		source   string
	}{
		{
			name: "Helm chart with invalid YAML helper",
			prepare: func(t *testing.T, dir string) string {
				return createTestHelmChartHelper(t, dir, "example")
			},
			manifest: "helper.yaml",
			content:  "pattern: \"v?\\d+\"\n",
			kind:     "Deployment",
			source:   reporthandling.SourceTypeHelmChart,
		},
		{
			name: "parent directory with Helm chart and invalid JSON helper",
			prepare: func(t *testing.T, dir string) string {
				createTestHelmChartHelper(t, dir, "example")
				return dir
			},
			manifest: "helper.json",
			content:  "{\"title\": \"{{ include \"example\" . }}\"}\n",
			kind:     "Deployment",
			source:   reporthandling.SourceTypeHelmChart,
		},
		{
			name: "Terraform directory",
			prepare: func(t *testing.T, dir string) string {
				writeTerraformFixture(t, dir, terraformPodFixture)
				return dir
			},
			kind:   "Pod",
			source: "Terraform",
		},
		{
			name: "directory with generated Kustomize resource",
			prepare: func(t *testing.T, dir string) string {
				app := filepath.Join(dir, "app")
				require.NoError(t, os.Mkdir(app, 0o750))
				require.NoError(t, os.WriteFile(filepath.Join(app, "kustomization.yaml"), []byte("configMapGenerator:\n  - name: generated\n    literals:\n      - key=value\n"), 0o600))
				return dir
			},
			kind:   "ConfigMap",
			source: reporthandling.SourceTypeKustomizeDirectory,
		},
		{
			name: "empty Helm chart",
			prepare: func(t *testing.T, dir string) string {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "Chart.yaml"), []byte("apiVersion: v2\nname: empty\nversion: 0.1.0\n"), 0o600))
				return dir
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := tc.prepare(t, t.TempDir())
			name, content := tc.manifest, tc.content
			if name == "" {
				name, content = "bad.yaml", "pattern: \"v?\\d+\"\n"
			}
			invalid := filepath.Join(dir, name)
			require.NoError(t, os.WriteFile(invalid, []byte(content), 0o600))

			sources, workloads, skips, err := getResourcesFromPath(context.Background(), dir, cautils.HelmValueOptions{}, nil)
			if tc.kind == "" {
				require.ErrorIs(t, err, cautils.ErrManifestsNotLoaded)
				assert.Empty(t, workloads)
			} else {
				require.NoError(t, err)
				require.Len(t, workloads, 1)
				assert.Equal(t, tc.kind, workloads[0].GetKind())
				assert.Equal(t, tc.source, sources[workloads[0].GetID()].FileType)
			}
			require.Len(t, skips, 1)
			assert.Equal(t, invalid, skips[0].Path)
			assert.Contains(t, skips[0].Reason, "parse error")

			_, _, _, err = getResourcesFromPath(context.Background(), invalid, cautils.HelmValueOptions{}, nil)
			require.ErrorIs(t, err, cautils.ErrManifestsNotLoaded)
		})
	}
}

const terraformPodFixture = `
resource "kubernetes_pod_v1" "example" {
  metadata {
    name      = "terraform-pod"
    namespace = "default"
  }
  spec {
    container {
      name  = "pause"
      image = "registry.k8s.io/pause:3.9"
    }
  }
}
`

func writeTerraformFixture(t *testing.T, dir, contents string) string {
	t.Helper()
	path := filepath.Join(dir, "main.tf")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func TestGetResourcesFromPathLoadsTerraformOnlyDirectory(t *testing.T) {
	dir := t.TempDir()
	path := writeTerraformFixture(t, dir, terraformPodFixture)

	sources, workloads, skips, err := getResourcesFromPath(context.Background(), dir, cautils.HelmValueOptions{}, nil)

	require.NoError(t, err)
	assert.Empty(t, skips)
	require.Len(t, workloads, 1)
	assert.Equal(t, "Pod", workloads[0].GetKind())
	assert.Equal(t, "terraform-pod", workloads[0].GetName())
	source := sources[workloads[0].GetID()]
	assert.Equal(t, "Terraform", source.FileType)
	assert.Equal(t, filepath.Base(path), source.RelativePath)
}

func TestGetResourcesFromPathLoadsExplicitTerraformFile(t *testing.T) {
	dir := t.TempDir()
	path := writeTerraformFixture(t, dir, terraformPodFixture)

	_, workloads, _, err := getResourcesFromPath(context.Background(), path, cautils.HelmValueOptions{}, nil)

	require.NoError(t, err)
	require.Len(t, workloads, 1)
	assert.Equal(t, "terraform-pod", workloads[0].GetName())
}

// Regression for issue-3348: the Terraform loader used to only inspect the
// single directory it was pointed at, unlike the Helm/Kustomize loaders which
// both discover their configs recursively. A module living below the scan
// root (the common modules/<name>/*.tf layout) was silently never scanned.
//
// This scenario mirrors a real modular Terraform repo: a plain YAML manifest
// sits at the root alongside a module directory. Pre-fix, the YAML manifest
// alone was enough for the scan to "succeed" while the module's resource
// vanished with no error and no warning - the worst kind of false negative.
func TestGetResourcesFromPathLoadsTerraformModuleInSubdirectory(t *testing.T) {
	dir := t.TempDir()
	moduleDir := filepath.Join(dir, "modules", "foo")
	require.NoError(t, os.MkdirAll(moduleDir, 0o750))
	writeTerraformFixture(t, moduleDir, terraformPodFixture)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(`
apiVersion: v1
kind: ConfigMap
metadata:
  name: yaml-config
`), 0o600))

	sources, workloads, skips, err := getResourcesFromPath(context.Background(), dir, cautils.HelmValueOptions{}, nil)

	require.NoError(t, err)
	assert.Empty(t, skips)
	resources := map[string]bool{}
	for _, workload := range workloads {
		resources[workload.GetKind()+"/"+workload.GetName()] = true
	}
	assert.Equal(t, map[string]bool{
		"ConfigMap/yaml-config": true,
		"Pod/terraform-pod":     true,
	}, resources, "resource defined only in modules/foo/main.tf must be found when scanning the repo root, not silently dropped")

	for _, workload := range workloads {
		if workload.GetKind() == "Pod" {
			source := sources[workload.GetID()]
			assert.Equal(t, "Terraform", source.FileType)
		}
	}
}

func TestGetResourcesFromPathReturnsTerraformErrorForMalformedTerraformOnlyDirectory(t *testing.T) {
	dir := t.TempDir()
	writeTerraformFixture(t, dir, `resource "kubernetes_pod_v1" "broken" {`)

	sources, workloads, skips, err := getResourcesFromPath(context.Background(), dir, cautils.HelmValueOptions{}, nil)

	require.Error(t, err)
	assert.Nil(t, sources)
	assert.Nil(t, workloads)
	assert.Empty(t, skips)
	assert.Contains(t, err.Error(), "failed to render Terraform resources")
	assert.NotContains(t, err.Error(), "no YAML or JSON manifest files")
}

func TestGetResourcesFromPathKeepsNoManifestErrorForUnsupportedTerraformOnlyDirectory(t *testing.T) {
	dir := t.TempDir()
	writeTerraformFixture(t, dir, `resource "null_resource" "example" {}`)

	sources, workloads, skips, err := getResourcesFromPath(context.Background(), dir, cautils.HelmValueOptions{}, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, cautils.ErrNoManifestFiles)
	assert.Nil(t, sources)
	assert.Nil(t, workloads)
	assert.Empty(t, skips)
}

func TestGetResourcesFromPathLoadsMixedYamlAndTerraformDirectory(t *testing.T) {
	dir := t.TempDir()
	writeTerraformFixture(t, dir, terraformPodFixture)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(`
apiVersion: v1
kind: ConfigMap
metadata:
  name: yaml-config
`), 0o600))

	_, workloads, _, err := getResourcesFromPath(context.Background(), dir, cautils.HelmValueOptions{}, nil)

	require.NoError(t, err)
	resources := map[string]bool{}
	for _, workload := range workloads {
		resources[workload.GetKind()+"/"+workload.GetName()] = true
	}
	assert.Equal(t, map[string]bool{
		"ConfigMap/yaml-config": true,
		"Pod/terraform-pod":     true,
	}, resources)
}

func TestGetResourcesFromPathPropagatesKustomizeFailure(t *testing.T) {
	dir := t.TempDir()
	kustomization := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - missing.yaml
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte(kustomization), 0o600))

	sources, workloads, _, err := getResourcesFromPath(context.Background(), dir, cautils.HelmValueOptions{}, nil)

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

	_, workloads, _, err := getResourcesFromPath(context.Background(), repoRoot, cautils.HelmValueOptions{}, nil)
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

	_, workloads, _, err := getResourcesFromPath(context.Background(), repoRoot, cautils.HelmValueOptions{}, nil)
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
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
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

// TestGetResourcesFromPath_RepositoryReachedThroughSymlink verifies that a scan of a
// repository reached through a symlinked path still reports repository-relative
// paths. go-git resolves the repository root, while discovered files keep the path
// the scan was given; on macOS every temporary directory is such a path (/var is a
// link to /private/var). Comparing the two forms produced "../<link>/..." or a
// climb to the filesystem root, which SARIF and GitLab then reported as files
// outside the repository.
func TestGetResourcesFromPath_RepositoryReachedThroughSymlink(t *testing.T) {
	const manifest = "k8s/pod.yaml"
	repoRoot := newRepoWithUnusableGitMetadata(t, manifest)

	link := filepath.Join(t.TempDir(), "linked-repo")
	if err := os.Symlink(repoRoot, link); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	tests := []struct {
		name     string
		scanPath string
	}{
		// the link itself is the root: discovery used to list nothing below it
		{name: "repository root scan", scanPath: link},
		{name: "directory scan", scanPath: filepath.Join(link, "k8s")},
		{name: "single file scan", scanPath: filepath.Join(link, filepath.FromSlash(manifest))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workloadIDToSource, workloads, _, err := getResourcesFromPath(context.Background(), tt.scanPath, cautils.HelmValueOptions{}, nil)
			require.NoError(t, err)
			require.Len(t, workloads, 1)

			src, ok := workloadIDToSource[workloads[0].GetID()]
			require.True(t, ok, "the workload must have a source")
			assert.Equal(t, repoRoot, src.Path)
			assert.Equal(t, manifest, filepath.ToSlash(src.RelativePath))
		})
	}
}

// TestGetResources_SymlinkedInputOutsideWorkspace pins that following a scan
// input that is itself a symlink does not read past the workspace: the link is
// inside it, its target is not.
func TestGetResources_SymlinkedInputOutsideWorkspace(t *testing.T) {
	wsDir := t.TempDir()
	outsideDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outsideDir, "pod.yaml"), []byte(singlePodManifest), 0o600))
	link := filepath.Join(wsDir, "linked")
	if err := os.Symlink(outsideDir, link); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	scanInfo := &cautils.ScanInfo{InputPatterns: []string{link}, WorkspaceDir: wsDir}
	session := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)

	_, workloads, _, _, _ := NewFileResourceHandler().GetResources(context.Background(), session, scanInfo)
	assert.Empty(t, workloads, "a manifest outside the workspace must not be loaded")
	require.Len(t, session.SkippedManifests, 1)
	assert.Equal(t, filepath.Join(link, "pod.yaml"), session.SkippedManifests[0].Path)
	assert.Contains(t, session.SkippedManifests[0].Reason, "escapes workspace root")
}

func TestHelmValueOptionsFromScanInfo(t *testing.T) {
	assert.True(t, helmValueOptionsFromScanInfo(nil).IsEmpty())

	scanInfo := &cautils.ScanInfo{
		HelmValueFiles:       []string{"values.yaml"},
		HelmSetValues:        []string{"replicas=2"},
		HelmSetStringValues:  []string{"image.tag=1.27"},
		HelmSetFileValues:    []string{"tls.crt=cert.pem"},
		HelmReleaseName:      "web",
		HelmReleaseNamespace: "shop",
		HelmKubeVersion:      "1.31",
		HelmAPIVersions:      []string{"gateway.networking.k8s.io/v1"},
	}

	assert.Equal(t, cautils.HelmValueOptions{
		ValueFiles:       []string{"values.yaml"},
		Values:           []string{"replicas=2"},
		StringValues:     []string{"image.tag=1.27"},
		FileValues:       []string{"tls.crt=cert.pem"},
		ReleaseName:      "web",
		ReleaseNamespace: "shop",
		KubeVersion:      "1.31",
		APIVersions:      []string{"gateway.networking.k8s.io/v1"},
	}, helmValueOptionsFromScanInfo(scanInfo))
}

func TestSharedRoot(t *testing.T) {
	abs := func(path string) string {
		return filepath.Join(string(filepath.Separator), filepath.FromSlash(path))
	}
	roots := func(paths ...string) []loadedInput {
		inputs := make([]loadedInput, len(paths))
		for i, path := range paths {
			if path != "" {
				path = abs(path)
			}
			inputs[i] = loadedInput{root: path}
		}
		return inputs
	}
	for _, tc := range []struct {
		name   string
		inputs []loadedInput
		want   string
	}{
		{name: "no inputs", inputs: nil, want: ""},
		{name: "single root", inputs: roots("w/dev"), want: ""},
		{name: "one git root for every input", inputs: roots("repo", "repo"), want: ""},
		{name: "siblings", inputs: roots("w/dev", "w/prod"), want: abs("w")},
		{name: "nested", inputs: roots("w", "w/apps"), want: abs("w")},
		{name: "deeper siblings", inputs: roots("w/a/k8s", "w/b/k8s", "w/a/x"), want: abs("w")},
		{name: "cloned repository ignored", inputs: roots("", "w/dev"), want: ""},
		{name: "cloned repository beside two roots", inputs: roots("w/dev", "", "w/prod"), want: abs("w")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sharedRoot(context.Background(), tc.inputs))
		})
	}

	t.Run("separate volumes", func(t *testing.T) {
		if filepath.VolumeName(`C:\`) == "" {
			t.Skip("volumes exist on Windows only")
		}
		assert.Equal(t, "", sharedRoot(context.Background(), []loadedInput{{root: `C:\dev`}, {root: `D:\prod`}}))
	})
}

func TestAnchorInputsKeepsRootsApart(t *testing.T) {
	abs := func(path string) string {
		return filepath.Join(string(filepath.Separator), filepath.FromSlash(path))
	}
	// pods builds an input holding a default/app Pod for each recorded path.
	pods := func(root, remote string, paths ...string) loadedInput {
		input := loadedInput{root: root, remote: remote, sources: map[string]reporthandling.Source{}}
		for _, p := range paths {
			lw := localworkload.NewLocalWorkload(map[string]interface{}{
				"apiVersion": "v1", "kind": "Pod",
				"metadata": map[string]interface{}{"name": "app", "namespace": "default"},
			})
			lw.SetPath(filepath.FromSlash(p))
			input.workloads = append(input.workloads, lw)
			input.sources[lw.GetID()] = reporthandling.Source{
				Path: root, RelativePath: filepath.FromSlash(strings.TrimSuffix(p, ":0")), FileType: reporthandling.SourceTypeYaml,
			}
		}
		return input
	}
	type entry struct{ path, sourcePath, relativePath string }
	entries := func(inputs []loadedInput) []entry {
		var got []entry
		for _, input := range inputs {
			for _, w := range input.workloads {
				lw := w.(*localworkload.LocalWorkload)
				source, ok := input.sources[lw.GetID()]
				require.True(t, ok, "every workload keeps its source under its new ID")
				got = append(got, entry{filepath.ToSlash(lw.GetPath()), source.Path, filepath.ToSlash(source.RelativePath)})
			}
		}
		return got
	}

	for _, tc := range []struct {
		name   string
		inputs []loadedInput
		want   []entry
	}{
		{
			name:   "local roots share a parent",
			inputs: []loadedInput{pods(abs("w/dev"), "", "pod.yaml:0"), pods(abs("w/prod"), "", "pod.yaml:0")},
			want:   []entry{{"dev/pod.yaml:0", abs("w"), "dev/pod.yaml"}, {"prod/pod.yaml:0", abs("w"), "prod/pod.yaml"}},
		},
		{
			name:   "local root beside a cloned repository",
			inputs: []loadedInput{pods(abs("w"), "", "dev/pod.yaml:0"), pods("", "github.com/o/r", "dev/pod.yaml:0")},
			want:   []entry{{"dev/pod.yaml:0", abs("w"), "dev/pod.yaml"}, {"github.com/o/r/dev/pod.yaml:0", "", "dev/pod.yaml"}},
		},
		{
			name:   "two cloned repositories",
			inputs: []loadedInput{pods("", "github.com/o/a", "pod.yaml:0"), pods("", "github.com/o/b", "pod.yaml:0")},
			want:   []entry{{"github.com/o/a/pod.yaml:0", "", "pod.yaml"}, {"github.com/o/b/pod.yaml:0", "", "pod.yaml"}},
		},
		{
			name:   "one cloned repository read twice",
			inputs: []loadedInput{pods("", "github.com/o/r", "dev/pod.yaml:0"), pods("", "github.com/o/r", "prod/pod.yaml:0")},
			want:   []entry{{"dev/pod.yaml:0", "", "dev/pod.yaml"}, {"prod/pod.yaml:0", "", "prod/pod.yaml"}},
		},
		{
			name:   "one local root",
			inputs: []loadedInput{pods(abs("w"), "", "dev/pod.yaml:0"), pods(abs("w"), "", "prod/pod.yaml:0")},
			want:   []entry{{"dev/pod.yaml:0", abs("w"), "dev/pod.yaml"}, {"prod/pod.yaml:0", abs("w"), "prod/pod.yaml"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			anchorInputs(context.Background(), tc.inputs)
			assert.Equal(t, tc.want, entries(tc.inputs))
		})
	}
}

func TestGetResources_MultiInputPartialFailureRecoversValidManifests(t *testing.T) {
	dir := t.TempDir()
	validYaml := filepath.Join(dir, "pod.yaml")
	require.NoError(t, os.WriteFile(validYaml, []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: my-pod\nspec:\n  containers:\n  - name: c\n    image: nginx\n"), 0o600))

	brokenChartDir := filepath.Join(dir, "brokenchart")
	require.NoError(t, os.MkdirAll(filepath.Join(brokenChartDir, "templates"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(brokenChartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: broken\nversion: 0.1.0\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(brokenChartDir, "templates", "sa.yaml"), []byte("apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: {{ required \"missing\" .Values.nonexistent }}\n"), 0o600))

	match := reporthandling.RuleMatchObjects{
		APIGroups:   []string{""},
		APIVersions: []string{"v1"},
		Resources:   []string{"pods"},
	}
	framework := *mockFramework("test-framework", []reporthandling.Control{
		mockControl("test-control", []reporthandling.PolicyRule{
			mockRule("test-rule", []reporthandling.RuleMatchObjects{match}, ""),
		}),
	})

	// Multi-input scan: one valid manifest, one broken chart
	scanInfo := &cautils.ScanInfo{
		InputPatterns: []string{brokenChartDir, validYaml},
	}
	session := cautils.NewOPASessionObj(context.Background(), []reporthandling.Framework{framework}, nil, scanInfo, nil)

	_, allResources, _, _, err := NewFileResourceHandler().GetResources(context.Background(), session, scanInfo)
	require.NoError(t, err, "multi-input scan must not fail when at least one input is valid")
	require.NotEmpty(t, allResources, "valid manifests must be loaded despite broken chart")

	var names []string
	for _, res := range allResources {
		names = append(names, res.GetName())
	}
	assert.Contains(t, names, "my-pod")

	// Verify broken chart is recorded in SkippedManifests
	require.NotEmpty(t, session.SkippedManifests)
	foundSkip := false
	for _, sk := range session.SkippedManifests {
		if strings.Contains(sk.Path, "brokenchart") {
			foundSkip = true
			break
		}
	}
	assert.True(t, foundSkip, "broken chart must be recorded in SkippedManifests")
}

func TestGetResources_SingleBrokenInputFailsPromptly(t *testing.T) {
	dir := t.TempDir()
	brokenChartDir := filepath.Join(dir, "brokenchart")
	require.NoError(t, os.MkdirAll(filepath.Join(brokenChartDir, "templates"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(brokenChartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: broken\nversion: 0.1.0\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(brokenChartDir, "templates", "sa.yaml"), []byte("apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: {{ required \"missing\" .Values.nonexistent }}\n"), 0o600))

	// Single input that fails must still return error promptly
	scanInfo := &cautils.ScanInfo{
		InputPatterns: []string{brokenChartDir},
	}
	session := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)

	_, _, _, _, err := NewFileResourceHandler().GetResources(context.Background(), session, scanInfo)
	require.Error(t, err, "single broken input must return error")
	assert.ErrorIs(t, err, cautils.ErrHelmRenderFailed)
}

func createTestHelmChartHelper(t *testing.T, baseDir, chartName string) string {
	chartDir := filepath.Join(baseDir, chartName)
	require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "templates"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte(fmt.Sprintf("apiVersion: v2\nname: %s\nversion: 0.1.0\n", chartName)), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "values.yaml"), []byte("replicaCount: 1\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "templates", "deployment.yaml"), []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo-deploy
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: demo
    spec:
      containers:
      - name: demo
        image: nginx:latest
`), 0o600))
	return chartDir
}

func TestGetWorkloadFromHelmChart_WorkspaceContainment(t *testing.T) {
	wsDir := t.TempDir()
	outsideDir := t.TempDir()

	inWsChart := createTestHelmChartHelper(t, wsDir, "in-ws-chart")
	outsideChart := createTestHelmChartHelper(t, outsideDir, "outside-chart")

	outsideValFile := filepath.Join(outsideDir, "outside-vals.yaml")
	require.NoError(t, os.WriteFile(outsideValFile, []byte("replicaCount: 2\n"), 0o600))

	outsideSecretFile := filepath.Join(outsideDir, "secret.txt")
	require.NoError(t, os.WriteFile(outsideSecretFile, []byte("super-secret\n"), 0o600))

	workloadRelPath := filepath.Join(inWsChart, "templates", "deployment.yaml")

	t.Run("chart outside workspace is rejected", func(t *testing.T) {
		outsideWlPath := filepath.Join(outsideChart, "templates", "deployment.yaml")
		_, _, err := getWorkloadFromHelmChart(context.Background(), outsideChart, outsideChart, outsideWlPath, cautils.HelmValueOptions{}, 0, wsDir)
		require.Error(t, err)
		assert.ErrorIs(t, err, pathcontainment.ErrPathEscapesWorkspace)
	})

	t.Run("values file outside workspace is rejected", func(t *testing.T) {
		valueOpts := cautils.HelmValueOptions{
			ValueFiles: []string{outsideValFile},
		}
		_, _, err := getWorkloadFromHelmChart(context.Background(), inWsChart, inWsChart, workloadRelPath, valueOpts, 0, wsDir)
		require.Error(t, err)
		assert.ErrorIs(t, err, pathcontainment.ErrPathEscapesWorkspace)
	})

	t.Run("set-file outside workspace is rejected", func(t *testing.T) {
		valueOpts := cautils.HelmValueOptions{
			FileValues: []string{"secret=" + outsideSecretFile},
		}
		_, _, err := getWorkloadFromHelmChart(context.Background(), inWsChart, inWsChart, workloadRelPath, valueOpts, 0, wsDir)
		require.Error(t, err)
		assert.ErrorIs(t, err, pathcontainment.ErrPathEscapesWorkspace)
	})

	t.Run("valid in-workspace chart and files succeed", func(t *testing.T) {
		inWsValFile := filepath.Join(wsDir, "in-ws-vals.yaml")
		require.NoError(t, os.WriteFile(inWsValFile, []byte("replicaCount: 3\n"), 0o600))

		valueOpts := cautils.HelmValueOptions{
			ValueFiles: []string{inWsValFile},
		}
		sources, workloads, err := getWorkloadFromHelmChart(context.Background(), inWsChart, inWsChart, workloadRelPath, valueOpts, 0, wsDir)
		require.NoError(t, err)
		assert.NotEmpty(t, sources)
		assert.Len(t, workloads, 1)
		assert.Equal(t, "demo-deploy", workloads[0].GetName())
	})

	t.Run("omitted workspace permits outside chart without containment error", func(t *testing.T) {
		outsideWlPath := filepath.Join(outsideChart, "templates", "deployment.yaml")
		sources, workloads, err := getWorkloadFromHelmChart(context.Background(), outsideChart, outsideChart, outsideWlPath, cautils.HelmValueOptions{}, 0)
		require.NoError(t, err)
		assert.NotEmpty(t, sources)
		assert.Len(t, workloads, 1)
	})
}

func TestGetResources_ChartAndFileRoute_RelativePaths(t *testing.T) {
	ctx := context.Background()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	chart := createTestHelmChartHelper(t, dir, "chart")
	templateDir := filepath.Join(chart, "templates")
	t.Chdir(dir)

	assertScan := func(t *testing.T, filePath, workspaceDir, wantRoot, wantRelativePath string) {
		t.Helper()
		filePath = filepath.FromSlash(filePath)
		scanInfo := &cautils.ScanInfo{
			InputPatterns: []string{filePath},
			ChartPath:     filepath.FromSlash("./chart"),
			FilePath:      filePath,
			WorkspaceDir:  workspaceDir,
			ScanObject:    scanObject("apps/v1", "Deployment", "", "demo-deploy"),
		}
		session := cautils.NewOPASessionObj(ctx, nil, nil, scanInfo, nil)

		_, workloads, _, _, err := NewFileResourceHandler().GetResources(ctx, session, scanInfo)
		require.NoError(t, err)
		require.Len(t, workloads, 1)
		require.NotNil(t, session.SingleResourceScan)
		assert.Equal(t, "demo-deploy", session.SingleResourceScan.GetName())
		for id := range workloads {
			source, ok := session.ResourceSource[id]
			require.True(t, ok, "missing source for %s", id)
			assert.Equal(t, wantRoot, source.Path)
			assert.Equal(t, wantRelativePath, source.RelativePath)
			assert.Equal(t, chart, source.HelmPath)
		}
	}

	t.Run("direct template path", func(t *testing.T) {
		assertScan(t, "./chart/templates/deployment.yaml", "", templateDir, "deployment.yaml")
	})
	t.Run("template reached through symlink", func(t *testing.T) {
		if err := os.Symlink(chart, filepath.Join(dir, "alias")); err != nil {
			t.Skipf("symlinks are unavailable: %v", err)
		}
		assertScan(t, "./alias/templates/deployment.yaml", dir, templateDir, "deployment.yaml")
	})
	t.Run("template in Git repository", func(t *testing.T) {
		_, err := gitv5.PlainInit(dir, false)
		require.NoError(t, err)
		assertScan(t, "./chart/templates/deployment.yaml", "", dir, filepath.FromSlash("chart/templates/deployment.yaml"))
	})
}

func TestGetResources_ChartAndFileRoute_SymlinkParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows resolves parent path components lexically")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	chart := createTestHelmChartHelper(t, dir, "chart")
	templates := filepath.Join(chart, "templates")
	targetDir := filepath.Join(templates, "other")
	linkTarget := filepath.Join(targetDir, "empty")
	require.NoError(t, os.MkdirAll(linkTarget, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(targetDir, "deployment.yaml"), []byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: linked-deploy\n"), 0o600))
	if err := os.Symlink(linkTarget, filepath.Join(templates, "link")); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	t.Chdir(dir)
	filePath := filepath.FromSlash("./chart/templates/link/../deployment.yaml")
	scanInfo := &cautils.ScanInfo{
		InputPatterns: []string{filePath},
		ChartPath:     filepath.FromSlash("./chart"),
		FilePath:      filePath,
		WorkspaceDir:  dir,
		ScanObject:    scanObject("apps/v1", "Deployment", "", "linked-deploy"),
	}
	ctx := context.Background()
	session := cautils.NewOPASessionObj(ctx, nil, nil, scanInfo, nil)

	_, workloads, _, _, err := NewFileResourceHandler().GetResources(ctx, session, scanInfo)
	require.NoError(t, err)
	require.Len(t, workloads, 1)
	for id := range workloads {
		source := session.ResourceSource[id]
		assert.Equal(t, targetDir, source.Path)
		assert.Equal(t, "deployment.yaml", source.RelativePath)
	}
}

func TestGetWorkloadFromHelmChart_AmbiguousTemplateAlias(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	chart := createTestHelmChartHelper(t, dir, "chart")
	templatePath := filepath.Join(chart, "templates", "deployment.yaml")
	aliasPath := filepath.Join(dir, "alias.yaml")
	if err := os.Symlink(templatePath, aliasPath); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	require.NoError(t, os.Symlink(templatePath, filepath.Join(chart, "templates", "second.yaml")))

	_, _, err := getWorkloadFromHelmChart(ctx, aliasPath, chart, aliasPath, cautils.HelmValueOptions{}, 0)
	require.ErrorContains(t, err, "matches multiple templates")
	_, workloads, err := getWorkloadFromHelmChart(ctx, templatePath, chart, templatePath, cautils.HelmValueOptions{}, 0)
	require.NoError(t, err)
	require.Len(t, workloads, 1)
}

func TestGetWorkloadFromHelmChart_PackagedDependency(t *testing.T) {
	chart := createTestHelmChartHelper(t, t.TempDir(), "chart")
	dependency := &helmchart.Chart{
		Metadata:  &helmchart.Metadata{APIVersion: "v2", Name: "child", Version: "0.1.0"},
		Templates: []*helmchart.File{{Name: "templates/pod.yaml", Data: []byte(singlePodManifest)}},
	}
	chartsDir := filepath.Join(chart, "charts")
	_, err := helmchartutil.Save(dependency, chartsDir)
	require.NoError(t, err)
	templatePath := filepath.Join(chartsDir, "child", "templates", "pod.yaml")

	assertTemplateMatch := func(t *testing.T) {
		t.Helper()
		_, workloads, err := getWorkloadFromHelmChart(context.Background(), templatePath, chart, templatePath, cautils.HelmValueOptions{}, 0)
		require.NoError(t, err)
		require.Len(t, workloads, 1)
		assert.Equal(t, "test-pod", workloads[0].GetName())
	}

	t.Run("missing dependency directory", func(t *testing.T) {
		_, err := os.Stat(templatePath)
		require.ErrorIs(t, err, os.ErrNotExist)
		assertTemplateMatch(t)
	})
	t.Run("ignored file at dependency directory", func(t *testing.T) {
		require.NoError(t, os.WriteFile(filepath.Join(chart, ".helmignore"), []byte("charts/child\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(chartsDir, "child"), []byte("ignored\n"), 0o600))
		_, err := os.Stat(templatePath)
		require.Error(t, err)
		if runtime.GOOS != "windows" {
			require.ErrorIs(t, err, syscall.ENOTDIR)
		}
		assertTemplateMatch(t)
	})
}

func TestGetResources_ChartAndFileRoute_EnforcesWorkspaceContainment(t *testing.T) {
	wsDir := t.TempDir()
	outsideDir := t.TempDir()

	inWsChart := createTestHelmChartHelper(t, wsDir, "ws-chart")
	outsideChart := createTestHelmChartHelper(t, outsideDir, "outside-chart")

	t.Run("rejects outside chart path when workspace configured", func(t *testing.T) {
		scanInfo := &cautils.ScanInfo{
			InputPatterns: []string{outsideChart},
			ChartPath:     outsideChart,
			FilePath:      filepath.Join(outsideChart, "templates", "deployment.yaml"),
			WorkspaceDir:  wsDir,
		}
		session := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)

		_, _, _, _, err := NewFileResourceHandler().GetResources(context.Background(), session, scanInfo)
		require.Error(t, err)
		assert.ErrorIs(t, err, pathcontainment.ErrPathEscapesWorkspace)
	})

	t.Run("rejects outside set-file when workspace configured", func(t *testing.T) {
		outsideFile := filepath.Join(outsideDir, "stolen.txt")
		require.NoError(t, os.WriteFile(outsideFile, []byte("payload\n"), 0o600))

		scanInfo := &cautils.ScanInfo{
			InputPatterns:     []string{inWsChart},
			ChartPath:         inWsChart,
			FilePath:          filepath.Join(inWsChart, "templates", "deployment.yaml"),
			WorkspaceDir:      wsDir,
			HelmSetFileValues: []string{"custom=" + outsideFile},
		}
		session := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)

		_, _, _, _, err := NewFileResourceHandler().GetResources(context.Background(), session, scanInfo)
		require.Error(t, err)
		assert.ErrorIs(t, err, pathcontainment.ErrPathEscapesWorkspace)
	})

	t.Run("permits in-workspace chart and files", func(t *testing.T) {
		scanInfo := &cautils.ScanInfo{
			InputPatterns: []string{inWsChart},
			ChartPath:     inWsChart,
			FilePath:      filepath.Join(inWsChart, "templates", "deployment.yaml"),
			WorkspaceDir:  wsDir,
		}
		session := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)

		_, _, _, _, err := NewFileResourceHandler().GetResources(context.Background(), session, scanInfo)
		require.NoError(t, err)
	})
}

func TestGetResources_IgnoreFileError(t *testing.T) {
	for _, tc := range []struct {
		name         string
		validFirst   bool
		includeValid bool
	}{
		{name: "single invalid input"},
		{name: "invalid then valid", includeValid: true},
		{name: "valid then invalid", includeValid: true, validFirst: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			badRoot := t.TempDir()
			// A directory is rejected portably, even when tests run as root.
			require.NoError(t, os.Mkdir(filepath.Join(badRoot, cautils.IgnoreFileName), 0o700))
			require.NoError(t, os.WriteFile(filepath.Join(badRoot, "bad.yaml"), []byte(singlePodManifest), 0o600))
			inputs := []string{badRoot}
			if tc.includeValid {
				validPath := filepath.Join(t.TempDir(), "pod.yaml")
				require.NoError(t, os.WriteFile(validPath, []byte(singlePodManifest), 0o600))
				if tc.validFirst {
					inputs = append([]string{validPath}, inputs...)
				} else {
					inputs = append(inputs, validPath)
				}
			}
			match := reporthandling.RuleMatchObjects{
				APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"pods"},
			}
			framework := *mockFramework("test-framework", []reporthandling.Control{
				mockControl("test-control", []reporthandling.PolicyRule{
					mockRule("test-rule", []reporthandling.RuleMatchObjects{match}, ""),
				}),
			})
			scanInfo := &cautils.ScanInfo{InputPatterns: inputs}
			session := cautils.NewOPASessionObj(context.Background(), []reporthandling.Framework{framework}, nil, scanInfo, nil)
			_, resources, _, _, err := NewFileResourceHandler().GetResources(context.Background(), session, scanInfo)
			if !tc.includeValid {
				require.ErrorIs(t, err, cautils.ErrIgnoreFileNotRegular)
				assert.Empty(t, resources)
				return
			}
			require.NoError(t, err)
			require.Len(t, resources, 1, "the valid input must still be scanned")
			require.Len(t, session.SkippedManifests, 1)
			assert.Equal(t, badRoot, session.SkippedManifests[0].Path)
			assert.Contains(t, session.SkippedManifests[0].Reason, cautils.ErrIgnoreFileNotRegular.Error())
			// The anonymizer hides this path in the reason.
			assert.Equal(t, filepath.Join(badRoot, cautils.IgnoreFileName), session.SkippedManifests[0].IgnoreFile)
		})
	}
}
