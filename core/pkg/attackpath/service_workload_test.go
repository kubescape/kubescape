package attackpath

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// svcResource builds a Service IMetadata object with the given selector.
// A nil selector means selector-less/headless.
func svcResource(namespace, name string, selector map[string]any) workloadinterface.IMetadata {
	spec := map[string]any{}
	if selector != nil {
		spec["selector"] = selector
	}
	return resource(map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata":   map[string]any{"name": name, "namespace": namespace},
		"spec":       spec,
	})
}

// typedSvc builds a typed corev1.Service with the given selector, for
// passing directly to ResolveServiceBackends.
func typedSvc(namespace, name string, selector map[string]string) corev1.Service {
	return corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       corev1.ServiceSpec{Selector: selector},
	}
}

// backendsFor finds the ServiceBackend for a given service name.
// Fails the test if not found.
func backendsFor(t *testing.T, results []ServiceBackend, name string) ServiceBackend {
	t.Helper()
	for _, r := range results {
		if r.ServiceName == name {
			return r
		}
	}
	t.Fatalf("no backend result found for service %q", name)
	return ServiceBackend{}
}

// --- ResolveServiceBackends tests ---

func TestResolveServiceBackends_MatchesDeploymentBySelector(t *testing.T) {
	svc := typedSvc("prod", "web-svc", map[string]string{"app": "web"})
	d := deploymentResource("prod", "web", map[string]any{"app": "web", "tier": "frontend"})

	results := ResolveServiceBackends([]corev1.Service{svc}, makeResources(d))

	r := backendsFor(t, results, "web-svc")
	if r.Headless {
		t.Error("expected Headless=false for a Service with a selector")
	}
	if len(r.Backends) != 1 || r.Backends[0].Name != "web" {
		t.Errorf("expected one backend 'web', got %+v", r.Backends)
	}
}

func TestResolveServiceBackends_SelectorLessServiceIsHeadless(t *testing.T) {
	// A Service with no selector at all: Headless=true, Backends empty.
	// The reliability bar says: "a selector-less/headless Service is
	// reported as skipped, not guessed."
	svc := typedSvc("prod", "headless-svc", nil)

	results := ResolveServiceBackends([]corev1.Service{svc}, makeResources())

	r := backendsFor(t, results, "headless-svc")
	if !r.Headless {
		t.Error("expected Headless=true for a selector-less Service")
	}
	if len(r.Backends) != 0 {
		t.Errorf("expected no backends for a headless Service, got %+v", r.Backends)
	}
}

func TestResolveServiceBackends_SelectorMatchesNothingIsNotHeadless(t *testing.T) {
	// A Service WITH a selector that matches no collected workload:
	// Headless=false, Backends empty. Different from a headless service.
	svc := typedSvc("prod", "orphan-svc", map[string]string{"app": "ghost"})
	d := deploymentResource("prod", "web", map[string]any{"app": "web"})

	results := ResolveServiceBackends([]corev1.Service{svc}, makeResources(d))

	r := backendsFor(t, results, "orphan-svc")
	if r.Headless {
		t.Error("expected Headless=false: Service has a selector, it just matches nothing")
	}
	if len(r.Backends) != 0 {
		t.Errorf("expected empty Backends when selector matches nothing, got %+v", r.Backends)
	}
}

func TestResolveServiceBackends_ServiceOnlySelectsWithinItsOwnNamespace(t *testing.T) {
	// A Service in "prod" must not match a Deployment in "staging" even if
	// the labels are identical.
	svc := typedSvc("prod", "web-svc", map[string]string{"app": "web"})
	dSameNS := deploymentResource("prod", "web-prod", map[string]any{"app": "web"})
	dOtherNS := deploymentResource("staging", "web-staging", map[string]any{"app": "web"})

	results := ResolveServiceBackends([]corev1.Service{svc}, makeResources(dSameNS, dOtherNS))

	r := backendsFor(t, results, "web-svc")
	if len(r.Backends) != 1 || r.Backends[0].Name != "web-prod" {
		t.Errorf("expected only the same-namespace backend, got %+v", r.Backends)
	}
}

func TestResolveServiceBackends_MultipleBackendsMatchedWhenLabelsOverlap(t *testing.T) {
	// Two Deployments carrying the same label should both appear as backends.
	svc := typedSvc("prod", "api-svc", map[string]string{"tier": "api"})
	d1 := deploymentResource("prod", "api-v1", map[string]any{"tier": "api", "version": "v1"})
	d2 := deploymentResource("prod", "api-v2", map[string]any{"tier": "api", "version": "v2"})

	results := ResolveServiceBackends([]corev1.Service{svc}, makeResources(d1, d2))

	r := backendsFor(t, results, "api-svc")
	if len(r.Backends) != 2 {
		t.Errorf("expected 2 backends for overlapping labels, got %+v", r.Backends)
	}
}

func TestResolveServiceBackends_WorkloadWithoutPodTemplateLabelsIsNotMatched(t *testing.T) {
	// A Job with no pod-template labels contributes no pod-label set to
	// match against: it must not appear as a backend.
	svc := typedSvc("prod", "svc", map[string]string{"app": "importer"})
	j := jobResourceNoTemplate("prod", "importer")

	results := ResolveServiceBackends([]corev1.Service{svc}, makeResources(j))

	r := backendsFor(t, results, "svc")
	if len(r.Backends) != 0 {
		t.Errorf("expected no backends for a Job with no pod-template labels, got %+v", r.Backends)
	}
}

func TestResolveServiceBackends_OutputIsDeterministicAcrossRuns(t *testing.T) {
	svc1 := typedSvc("alpha", "svc-a", map[string]string{"app": "a"})
	svc2 := typedSvc("beta", "svc-b", map[string]string{"app": "b"})
	da := deploymentResource("alpha", "a", map[string]any{"app": "a"})
	db := deploymentResource("beta", "b", map[string]any{"app": "b"})
	svcs := []corev1.Service{svc2, svc1} // deliberately reversed

	first := ResolveServiceBackends(svcs, makeResources(da, db))
	second := ResolveServiceBackends(svcs, makeResources(da, db))

	if len(first) != len(second) {
		t.Fatalf("run lengths differ: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].ServiceName != second[i].ServiceName || first[i].ServiceNamespace != second[i].ServiceNamespace {
			t.Errorf("position %d differs between runs: %+v vs %+v", i, first[i], second[i])
		}
	}
	// After sorting, alpha/svc-a must come before beta/svc-b.
	if first[0].ServiceNamespace != "alpha" {
		t.Errorf("expected alpha first after sort, got %+v", first[0])
	}
}

func TestResolveServiceBackends_EmptyInputsReturnEmpty(t *testing.T) {
	results := ResolveServiceBackends(nil, map[string]workloadinterface.IMetadata{})
	if len(results) != 0 {
		t.Errorf("expected empty result for nil services, got %+v", results)
	}
}

func TestResolveServiceBackends_ServiceNamespaceAndNameAreCarried(t *testing.T) {
	svc := typedSvc("payments", "checkout", map[string]string{"app": "checkout"})
	d := deploymentResource("payments", "checkout", map[string]any{"app": "checkout"})

	results := ResolveServiceBackends([]corev1.Service{svc}, makeResources(d))

	r := backendsFor(t, results, "checkout")
	if r.ServiceNamespace != "payments" {
		t.Errorf("expected ServiceNamespace 'payments', got %q", r.ServiceNamespace)
	}
	if r.ServiceName != "checkout" {
		t.Errorf("expected ServiceName 'checkout', got %q", r.ServiceName)
	}
}