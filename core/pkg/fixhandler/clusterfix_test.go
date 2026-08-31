package fixhandler

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clusterResource builds a resource the way a live-cluster scan records one: a
// plain Kubernetes object, with none of the localworkload path wrapping a file
// scan adds.
func clusterResource(kind, name string) *reporthandling.Resource {
	obj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       kind,
		"metadata": map[string]any{
			"name":            name,
			"namespace":       "default",
			"resourceVersion": "4242",
		},
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":            name,
							"image":           "nginx:latest",
							"securityContext": map[string]any{"privileged": true},
						},
					},
				},
			},
		},
		"status": map[string]any{"replicas": int64(1)},
	}
	return &reporthandling.Resource{
		ResourceID: "/apps/v1/default/" + kind + "/" + name,
		Object:     obj,
	}
}

// regoVectorResource is a rule finding spanning several related objects, as the
// RBAC and cloud controls produce. It is not one addressable manifest.
func regoVectorResource(t *testing.T) *reporthandling.Resource {
	t.Helper()
	// IsTypeRegoResponseVector keys off top-level "kind", "name" and
	// "relatedObjects" — note name at the root, not under metadata.
	obj := map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "RoleBinding",
		"name":       "binding",
		objectsenvelopes.RelatedObjectsKey: []any{
			map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": map[string]any{"name": "sa"}},
		},
	}
	require.True(t, objectsenvelopes.IsTypeRegoResponseVector(obj),
		"fixture must actually be a rego response vector, or the test proves nothing")
	return &reporthandling.Resource{ResourceID: "regovector-1", Object: obj}
}

func newClusterHandler(results []resourcesresults.Result, resources []reporthandling.Resource) *FixHandler {
	return &FixHandler{
		fixInfo: &metav1.FixInfo{},
		reportObj: &reporthandlingv2.PostureReport{
			Metadata: reporthandlingv2.Metadata{
				ScanMetadata: reporthandlingv2.ScanMetadata{
					ScanningTarget: reporthandlingv2.Cluster,
				},
				// Required, not decoration: Cluster is the zero enum value, so
				// the context is what distinguishes a real cluster scan from a
				// report that lost its scanningTarget.
				ContextMetadata: reporthandlingv2.ContextMetadata{
					ClusterContextMetadata: &reporthandlingv2.ClusterMetadata{ContextName: "kind-kind"},
				},
			},
			Results:   results,
			Resources: resources,
		},
	}
}

// --- report acceptance ----------------------------------------------------

// TestNewFixHandler_AcceptsClusterReport covers the whole load path, not just
// isSupportedScanningTarget: a cluster report has no local root, so the
// getLocalPath/os.Stat step had to be skipped too or loading would still fail.
func TestNewFixHandler_AcceptsClusterReport(t *testing.T) {
	report := reporthandlingv2.PostureReport{
		Metadata: reporthandlingv2.Metadata{
			ScanMetadata: reporthandlingv2.ScanMetadata{
				ScanningTarget: reporthandlingv2.Cluster,
			},
			ContextMetadata: reporthandlingv2.ContextMetadata{
				ClusterContextMetadata: &reporthandlingv2.ClusterMetadata{ContextName: "kind-kind"},
			},
		},
		Resources: []reporthandling.Resource{*clusterResource("Deployment", "nginx")},
	}
	raw, err := json.Marshal(report)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "cluster.json")
	require.NoError(t, os.WriteFile(path, raw, 0600))

	handler, err := NewFixHandler(&metav1.FixInfo{ReportFile: path})
	require.NoError(t, err, "a cluster report must load")
	require.NotNil(t, handler)
	assert.True(t, handler.isClusterReport())
}

func TestIsSupportedScanningTarget(t *testing.T) {
	targetReport := func(target reporthandlingv2.ScanningTarget, clusterCtx bool) *reporthandlingv2.PostureReport {
		report := &reporthandlingv2.PostureReport{
			Metadata: reporthandlingv2.Metadata{
				ScanMetadata: reporthandlingv2.ScanMetadata{ScanningTarget: target},
			},
		}
		if clusterCtx {
			report.Metadata.ContextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{ContextName: "dev"}
		}
		return report
	}

	t.Run("file-based targets are supported", func(t *testing.T) {
		for _, target := range []reporthandlingv2.ScanningTarget{
			reporthandlingv2.File,
			reporthandlingv2.Directory,
			reporthandlingv2.GitLocal,
		} {
			assert.NoErrorf(t, isSupportedScanningTarget(targetReport(target, false)),
				"target %d should be supported", target)
		}
	})

	t.Run("a cluster scan with its context is supported", func(t *testing.T) {
		assert.NoError(t, isSupportedScanningTarget(targetReport(reporthandlingv2.Cluster, true)))
	})

	t.Run("a bare zero target is not a cluster scan", func(t *testing.T) {
		// Cluster is the zero enum value, so this is indistinguishable from a
		// report that lost its scanningTarget. Accepting it would turn every
		// malformed report into an empty cluster scan.
		assert.Error(t, isSupportedScanningTarget(targetReport(reporthandlingv2.Cluster, false)))
	})

	t.Run("a remote repo scan is not supported", func(t *testing.T) {
		// Neither files nor live objects to work from.
		assert.Error(t, isSupportedScanningTarget(targetReport(reporthandlingv2.Repo, false)))
	})
}

// --- source resolution ----------------------------------------------------

func TestResolveResourceSource_Cluster(t *testing.T) {
	h := newClusterHandler(nil, nil)

	t.Run("a live workload is patched in memory", func(t *testing.T) {
		src := h.resolveResourceSource(context.Background(), clusterResource("Deployment", "nginx"))
		assert.True(t, src.inMemory)
		assert.Empty(t, src.skipReason)
		assert.Empty(t, src.filePath, "a cluster resource has no file to write")
		assert.Zero(t, src.documentIndex, "a rendered resource is always a single document")
	})

	t.Run("a rego response vector is skipped", func(t *testing.T) {
		src := h.resolveResourceSource(context.Background(), regoVectorResource(t))
		assert.False(t, src.inMemory)
		assert.Contains(t, src.skipReason, "not a single patchable workload")
	})

	t.Run("an incomplete object is skipped", func(t *testing.T) {
		res := &reporthandling.Resource{
			ResourceID: "broken",
			Object:     map[string]any{"metadata": map[string]any{"name": "x"}},
		}
		src := h.resolveResourceSource(context.Background(), res)
		assert.False(t, src.inMemory)
		assert.Contains(t, src.skipReason, "not a complete Kubernetes object")
	})
}

// --- preparation and rendering --------------------------------------------

func clusterResultFor(res *reporthandling.Resource, controls ...resourcesresults.ResourceAssociatedControl) resourcesresults.Result {
	return resourcesresults.Result{
		ResourceID:         res.GetID(),
		RawResource:        res,
		AssociatedControls: controls,
	}
}

func TestPrepareResourcesToFix_ClusterMarksInMemory(t *testing.T) {
	res := clusterResource("Deployment", "nginx")
	results := []resourcesresults.Result{
		clusterResultFor(res, failedControl("C-0057", "Privileged container",
			failedRuleWithFix("spec.template.spec.containers[0].securityContext.privileged", "false"),
		)),
	}
	h := newClusterHandler(results, []reporthandling.Resource{*res})

	toFix := h.PrepareResourcesToFix(context.Background())
	require.Len(t, toFix, 1)
	assert.True(t, toFix[0].inMemory)
	assert.Empty(t, toFix[0].FilePath)
	assert.NotEmpty(t, toFix[0].YamlExpressions)
}

func TestRenderFixes_ProducesPatchedManifest(t *testing.T) {
	res := clusterResource("Deployment", "nginx")
	results := []resourcesresults.Result{
		clusterResultFor(res, failedControl("C-0057", "Privileged container",
			failedRuleWithFix("spec.template.spec.containers[0].securityContext.privileged", "false"),
		)),
	}
	h := newClusterHandler(results, []reporthandling.Resource{*res})

	toFix := h.PrepareResourcesToFix(context.Background())
	rendered, errs := h.RenderFixes(context.Background(), toFix)

	assert.Empty(t, errs)
	require.Len(t, rendered, 1)
	assert.Contains(t, rendered[0].Manifest, "privileged: false")
	assert.NotContains(t, rendered[0].Manifest, "privileged: true")
	assert.NotContains(t, rendered[0].Manifest, "resourceVersion", "server-managed fields must not survive")
	assert.NotContains(t, rendered[0].Manifest, "status:")
	require.NotNil(t, rendered[0].Resource)
	assert.Equal(t, res.GetID(), rendered[0].Resource.GetID())
}

func TestRenderFixes_SkipsFileBackedResources(t *testing.T) {
	// RenderFixes and ApplyChanges must partition the same slice, so neither
	// acts twice on one resource.
	dir := t.TempDir()
	manifest := writeManifest(t, dir, "deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\n")
	rel, err := filepath.Rel(dir, manifest)
	require.NoError(t, err)
	res := buildResource(t, dir, rel, "Deployment", "demo", 0)

	results := []resourcesresults.Result{
		clusterResultFor(res, failedControl("C-0057", "Privileged container",
			failedRuleWithFix("spec.containers[0].securityContext.privileged", "false"),
		)),
	}
	h := newHandlerForResources(dir, results, []reporthandling.Resource{*res}, false)

	toFix := h.PrepareResourcesToFix(context.Background())
	require.NotEmpty(t, toFix)

	rendered, errs := h.RenderFixes(context.Background(), toFix)
	assert.Empty(t, errs)
	assert.Empty(t, rendered, "a file-backed resource belongs to ApplyChanges, not RenderFixes")
}

// TestApplyChanges_SkipsInMemoryResources is the counterpart guard: an empty
// FilePath must never reach the writer, or every cluster resource would be
// grouped under one nonexistent file.
func TestApplyChanges_SkipsInMemoryResources(t *testing.T) {
	res := clusterResource("Deployment", "nginx")
	h := newClusterHandler(nil, []reporthandling.Resource{*res})

	toFix := []ResourceFixInfo{{
		Resource:        res,
		inMemory:        true,
		YamlExpressions: map[string]armotypes.FixPath{"select(di==0).spec.a |= true": {}},
	}}

	updated, errs := h.ApplyChanges(context.Background(), toFix)
	assert.Zero(t, updated, "nothing on disk should have been touched")
	assert.Empty(t, errs)
}

// --- regression guard -----------------------------------------------------

// TestPrepareResourcesToFix_FileScanUnchanged pins that the cluster branch did
// not alter the file path this package already supported.
func TestPrepareResourcesToFix_FileScanUnchanged(t *testing.T) {
	dir := t.TempDir()
	manifest := writeManifest(t, dir, "deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\n")
	rel, err := filepath.Rel(dir, manifest)
	require.NoError(t, err)
	res := buildResource(t, dir, rel, "Deployment", "demo", 0)

	results := []resourcesresults.Result{
		clusterResultFor(res, failedControl("C-0057", "Privileged container",
			failedRuleWithFix("spec.containers[0].securityContext.privileged", "false"),
		)),
	}
	h := newHandlerForResources(dir, results, []reporthandling.Resource{*res}, false)

	toFix := h.PrepareResourcesToFix(context.Background())
	require.Len(t, toFix, 1)
	assert.False(t, toFix[0].inMemory)
	assert.Equal(t, manifest, toFix[0].FilePath, "the resolved manifest path must be unchanged")
}
