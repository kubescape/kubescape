package attackpath

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
)

// resource builds a minimal IMetadata object from a raw map, the same
// pattern used across networkpolicy, exposure, and rbacgraph adapter tests.
func resource(obj map[string]any) workloadinterface.IMetadata {
	return workloadinterface.NewWorkloadObj(obj)
}

func deploymentResource(namespace, name string, podTemplateLabels map[string]any) workloadinterface.IMetadata {
	return resource(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": name, "namespace": namespace},
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{"labels": podTemplateLabels},
			},
		},
	})
}

func podResource(namespace, name string, metaLabels map[string]any) workloadinterface.IMetadata {
	return resource(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "labels": metaLabels},
	})
}

func cronJobResource(namespace, name string, podTemplateLabels map[string]any) workloadinterface.IMetadata {
	return resource(map[string]any{
		"apiVersion": "batch/v1",
		"kind":       "CronJob",
		"metadata":   map[string]any{"name": name, "namespace": namespace},
		"spec": map[string]any{
			"jobTemplate": map[string]any{
				"spec": map[string]any{
					"template": map[string]any{
						"metadata": map[string]any{"labels": podTemplateLabels},
					},
				},
			},
		},
	})
}

func jobResourceNoTemplate(namespace, name string) workloadinterface.IMetadata {
	return resource(map[string]any{
		"apiVersion": "batch/v1",
		"kind":       "Job",
		"metadata":   map[string]any{"name": name, "namespace": namespace},
		"spec":       map[string]any{},
	})
}

func makeResources(items ...workloadinterface.IMetadata) map[string]workloadinterface.IMetadata {
	m := make(map[string]workloadinterface.IMetadata, len(items))
	for _, r := range items {
		m[r.GetID()] = r
	}
	return m
}

// --- PodTemplateLabels unit tests ---

func TestPodTemplateLabels_PodUsesOwnMetadataLabels(t *testing.T) {
	obj := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "web",
			"namespace": "prod",
			"labels":    map[string]any{"app": "web", "tier": "frontend"},
		},
	}
	got := PodTemplateLabels("Pod", obj)
	if got["app"] != "web" || got["tier"] != "frontend" {
		t.Errorf("PodTemplateLabels(Pod) = %v, want app=web tier=frontend", got)
	}
}

func TestPodTemplateLabels_DeploymentUsesSpecTemplatePath(t *testing.T) {
	obj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "api", "namespace": "prod"},
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{
					"labels": map[string]any{"app": "api", "version": "v2"},
				},
			},
		},
	}
	got := PodTemplateLabels("Deployment", obj)
	if got["app"] != "api" || got["version"] != "v2" {
		t.Errorf("PodTemplateLabels(Deployment) = %v, want app=api version=v2", got)
	}
}

func TestPodTemplateLabels_CronJobUsesDeepJobTemplatePath(t *testing.T) {
	obj := map[string]any{
		"apiVersion": "batch/v1",
		"kind":       "CronJob",
		"metadata":   map[string]any{"name": "cleaner", "namespace": "ops"},
		"spec": map[string]any{
			"jobTemplate": map[string]any{
				"spec": map[string]any{
					"template": map[string]any{
						"metadata": map[string]any{
							"labels": map[string]any{"job": "cleaner"},
						},
					},
				},
			},
		},
	}
	got := PodTemplateLabels("CronJob", obj)
	if got["job"] != "cleaner" {
		t.Errorf("PodTemplateLabels(CronJob) = %v, want job=cleaner", got)
	}
}

func TestPodTemplateLabels_MissingPathReturnsNil(t *testing.T) {
	obj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "empty", "namespace": "prod"},
		"spec":       map[string]any{},
	}
	if got := PodTemplateLabels("Deployment", obj); got != nil {
		t.Errorf("PodTemplateLabels with missing path = %v, want nil", got)
	}
}

// --- ResolveEndpointsFromResources tests ---

func TestResolveEndpoints_DeploymentFullyResolved(t *testing.T) {
	d := deploymentResource("prod", "web", map[string]any{"app": "web"})
	refs := []WorkloadRef{{Namespace: "prod", Kind: "Deployment", Name: "web"}}

	results := ResolveEndpointsFromResources(makeResources(d), refs)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if !r.Resolved {
		t.Fatalf("expected Resolved=true, got Reason=%q", r.Reason)
	}
	if r.Endpoint.Namespace != "prod" || r.Endpoint.Name != "web" {
		t.Errorf("unexpected endpoint identity: %+v", r.Endpoint)
	}
	if r.Endpoint.Labels["app"] != "web" {
		t.Errorf("expected labels to carry through, got %+v", r.Endpoint.Labels)
	}
}

func TestResolveEndpoints_PodUsesOwnLabels(t *testing.T) {
	p := podResource("dev", "runner", map[string]any{"component": "runner"})
	refs := []WorkloadRef{{Namespace: "dev", Kind: "Pod", Name: "runner"}}

	results := ResolveEndpointsFromResources(makeResources(p), refs)

	if len(results) != 1 || !results[0].Resolved {
		t.Fatalf("expected 1 resolved result, got %+v", results)
	}
	if results[0].Endpoint.Labels["component"] != "runner" {
		t.Errorf("expected component=runner, got %+v", results[0].Endpoint.Labels)
	}
}

func TestResolveEndpoints_CronJobResolved(t *testing.T) {
	cj := cronJobResource("ops", "nightly", map[string]any{"job": "nightly"})
	refs := []WorkloadRef{{Namespace: "ops", Kind: "CronJob", Name: "nightly"}}

	results := ResolveEndpointsFromResources(makeResources(cj), refs)

	if len(results) != 1 || !results[0].Resolved {
		t.Fatalf("expected 1 resolved result, got %+v", results)
	}
	if results[0].Endpoint.Labels["job"] != "nightly" {
		t.Errorf("expected job=nightly from deep CronJob path, got %+v", results[0].Endpoint.Labels)
	}
}

func TestResolveEndpoints_UnknownKindNotResolved(t *testing.T) {
	refs := []WorkloadRef{{Namespace: "prod", Kind: "MyCustomController", Name: "custom"}}

	results := ResolveEndpointsFromResources(map[string]workloadinterface.IMetadata{}, refs)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Resolved {
		t.Error("expected Resolved=false for an unknown kind")
	}
	if results[0].Reason == "" {
		t.Error("expected a non-empty Reason for an unknown kind")
	}
}

func TestResolveEndpoints_MissingFromResourcesNotResolved(t *testing.T) {
	refs := []WorkloadRef{{Namespace: "prod", Kind: "Deployment", Name: "ghost"}}

	results := ResolveEndpointsFromResources(map[string]workloadinterface.IMetadata{}, refs)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Resolved {
		t.Error("expected Resolved=false for a workload absent from resources")
	}
	if results[0].Reason == "" {
		t.Error("expected a non-empty Reason")
	}
}

func TestResolveEndpoints_JobWithNoPodTemplateLabelsNotResolved(t *testing.T) {
	// A Job that exists in resources but has no spec.template.metadata.labels
	// must not be guessed at: Resolved=false with a Reason.
	j := jobResourceNoTemplate("batch-ns", "importer")
	refs := []WorkloadRef{{Namespace: "batch-ns", Kind: "Job", Name: "importer"}}

	results := ResolveEndpointsFromResources(makeResources(j), refs)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Resolved {
		t.Error("expected Resolved=false when pod-template labels are absent")
	}
	if results[0].Reason == "" {
		t.Error("expected a non-empty Reason")
	}
}

func TestResolveEndpoints_OutputIsDeterministic(t *testing.T) {
	// Same inputs called twice must produce byte-identical ordering.
	// Expected sort: alpha/Deployment/app < alpha/Deployment/worker < beta/Deployment/app
	a := deploymentResource("alpha", "app", map[string]any{"x": "a"})
	b := deploymentResource("beta", "app", map[string]any{"x": "b"})
	c := deploymentResource("alpha", "worker", map[string]any{"x": "c"})
	refs := []WorkloadRef{
		{Namespace: "beta", Kind: "Deployment", Name: "app"},
		{Namespace: "alpha", Kind: "Deployment", Name: "worker"},
		{Namespace: "alpha", Kind: "Deployment", Name: "app"},
	}

	first := ResolveEndpointsFromResources(makeResources(a, b, c), refs)
	second := ResolveEndpointsFromResources(makeResources(a, b, c), refs)

	if len(first) != len(second) {
		t.Fatalf("run lengths differ: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].Ref != second[i].Ref {
			t.Errorf("position %d differs between runs: %+v vs %+v", i, first[i].Ref, second[i].Ref)
		}
	}
	if first[0].Ref.Namespace != "alpha" || first[0].Ref.Name != "app" {
		t.Errorf("position 0 should be alpha/app, got %+v", first[0].Ref)
	}
	if first[1].Ref.Namespace != "alpha" || first[1].Ref.Name != "worker" {
		t.Errorf("position 1 should be alpha/worker, got %+v", first[1].Ref)
	}
	if first[2].Ref.Namespace != "beta" {
		t.Errorf("position 2 should be beta, got %+v", first[2].Ref)
	}
}

func TestResolveEndpoints_NilResourceEntryIsSafe(t *testing.T) {
	resources := map[string]workloadinterface.IMetadata{"some-id": nil}
	refs := []WorkloadRef{{Namespace: "prod", Kind: "Deployment", Name: "web"}}

	// Must not panic; result is Resolved=false (not found after nil is skipped).
	results := ResolveEndpointsFromResources(resources, refs)
	if len(results) != 1 || results[0].Resolved {
		t.Errorf("expected 1 unresolved result for nil map entry, got %+v", results)
	}
}

func TestResolveEndpoints_EmptyRefsReturnsEmpty(t *testing.T) {
	results := ResolveEndpointsFromResources(map[string]workloadinterface.IMetadata{}, nil)
	if len(results) != 0 {
		t.Errorf("expected empty slice for nil refs, got %+v", results)
	}
}