package attackpath

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/networkpolicy"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	if r.Endpoint.Namespace != "prod" || r.Endpoint.Name != "" || r.Ref.Name != "web" {
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

func TestResolveEndpoints_HostNetworkPodIsReflectedOnEndpoint(t *testing.T) {
	// A Pod with spec.hostNetwork: true must produce Resolved=true with
	// HostNetwork=true on the returned Endpoint so the networkpolicy engine
	// classifies it as ExposureOpen rather than restricted.
	p := resource(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "hostnet",
			"namespace": "prod",
			"labels":    map[string]any{"app": "hostnet"},
		},
		"spec": map[string]any{
			"hostNetwork": true,
		},
	})
	resources := makeResources(p)
	refs := []WorkloadRef{{Namespace: "prod", Kind: "Pod", Name: "hostnet"}}

	results := ResolveEndpointsFromResources(resources, refs)

	if len(results) != 1 || !results[0].Resolved {
		t.Fatalf("expected 1 resolved result, got %+v", results)
	}
	if !results[0].Endpoint.HostNetwork {
		t.Error("expected HostNetwork=true for a Pod with spec.hostNetwork=true")
	}
}

func TestResolveEndpoints_DeploymentHostNetworkReflected(t *testing.T) {
	d := resource(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "hostnet-deploy", "namespace": "prod"},
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": "hostnet"}},
				"spec": map[string]any{
					"hostNetwork": true,
				},
			},
		},
	})
	resources := makeResources(d)
	refs := []WorkloadRef{{Namespace: "prod", Kind: "Deployment", Name: "hostnet-deploy"}}

	results := ResolveEndpointsFromResources(resources, refs)

	if len(results) != 1 || !results[0].Resolved {
		t.Fatalf("expected 1 resolved result, got %+v", results)
	}
	if !results[0].Endpoint.HostNetwork {
		t.Error("expected HostNetwork=true for a Deployment with hostNetwork=true in pod template")
	}
}

func TestResolveEndpoints_ControllerIdentityDoesNotBypassPolicies(t *testing.T) {
	deployment := deploymentResource("prod", "api", map[string]any{"app": "api"})
	stateful := deploymentResource("prod", "api", map[string]any{"app": "api"}).GetObject()
	stateful["kind"] = "StatefulSet"
	pod := podResource("prod", "api", map[string]any{"app": "api"})
	results := ResolveEndpointsFromResources(makeResources(deployment, resource(stateful), pod), []WorkloadRef{
		{Namespace: "prod", Kind: "Deployment", Name: "api"},
		{Namespace: "prod", Kind: "StatefulSet", Name: "api"},
		{Namespace: "prod", Kind: "Pod", Name: "api"},
	})
	endpoints := map[string]networkpolicy.Endpoint{}
	for _, r := range results {
		if !r.Resolved {
			t.Fatal(r.Reason)
		}
		endpoints[r.Ref.Kind] = r.Endpoint
	}
	idx, errs := networkpolicy.NewIndex([]*networkingv1.NetworkPolicy{{ObjectMeta: metav1.ObjectMeta{Name: "deny-all", Namespace: "prod"}, Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{}, PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}}}}, nil)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	for _, pair := range [][2]string{{"Deployment", "StatefulSet"}, {"Deployment", "Pod"}, {"Deployment", "Deployment"}, {"StatefulSet", "StatefulSet"}} {
		v, _, _ := idx.Reaches(endpoints[pair[0]], endpoints[pair[1]], nil)
		if v != networkpolicy.Denied {
			t.Errorf("%v: got %v, want Denied", pair, v)
		}
	}
	if v, _, _ := idx.Reaches(endpoints["Pod"], endpoints["Pod"], nil); v != networkpolicy.Allowed {
		t.Errorf("real Pod must retain self-access: %v", v)
	}
}

func TestResolveEndpoints_DuplicateManifestData(t *testing.T) {
	for _, tc := range []struct {
		name        string
		labels      map[string]any
		hostNetwork bool
		resolved    bool
	}{
		{name: "conflicting labels", labels: map[string]any{"app": "other"}},
		{name: "conflicting host network", labels: map[string]any{"app": "api"}, hostNetwork: true},
		{name: "identical endpoint data", labels: map[string]any{"app": "api"}, resolved: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := deploymentResource("prod", "api", map[string]any{"app": "api"})
			other := deploymentResource("prod", "api", tc.labels).GetObject()
			other["spec"].(map[string]any)["template"].(map[string]any)["spec"] = map[string]any{"hostNetwork": tc.hostNetwork}
			resources := map[string]workloadinterface.IMetadata{"first.yaml": first, "second.yaml": resource(other)}
			for i := 0; i < 30; i++ {
				results := ResolveEndpointsFromResources(resources, []WorkloadRef{{Namespace: "prod", Kind: "Deployment", Name: "api"}})
				if len(results) != 1 || results[0].Resolved != tc.resolved {
					t.Fatalf("expected resolved=%v, got %+v", tc.resolved, results)
				}
				if !tc.resolved && results[0].Reason == "" {
					t.Fatal("ambiguous result needs a reason")
				}
			}
		})
	}
}

func TestResolveEndpoints_UnlabeledPodCopiesAreEquivalent(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		absent := podResource("prod", "pod", nil).GetObject()
		delete(absent["metadata"].(map[string]any), "labels")
		first, second := resource(absent), podResource("prod", "pod", map[string]any{})
		if reverse {
			first, second = second, first
		}
		results := ResolveEndpointsFromResources(map[string]workloadinterface.IMetadata{"a": first, "b": second}, []WorkloadRef{{Namespace: "prod", Kind: "Pod", Name: "pod"}})
		if len(results) != 1 || !results[0].Resolved || len(results[0].Endpoint.Labels) != 0 {
			t.Fatalf("equivalent empty Pod labels must resolve: %+v", results)
		}
	}
}
