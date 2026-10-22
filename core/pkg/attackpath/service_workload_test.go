package attackpath

import (
	"reflect"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestResolveServiceBackends_DuplicateWorkloadLabels(t *testing.T) {
	web := map[string]any{"app": "web"}
	api := map[string]any{"app": "api"}
	for _, tt := range []struct {
		name       string
		first      map[string]any
		second     map[string]any
		third      map[string]any
		unresolved bool
	}{
		{name: "equivalent", first: web, second: map[string]any{"app": "web"}, third: web},
		{name: "conflicting", first: web, second: api, third: web, unresolved: true},
		{name: "missing labels", first: web, second: nil, third: web, unresolved: true},
	} {
		for _, reverse := range []bool{false, true} {
			name := tt.name + "/forward"
			if reverse {
				name = tt.name + "/reverse"
			}
			t.Run(name, func(t *testing.T) {
				first, second := tt.first, tt.second
				if reverse {
					first, second = second, first
				}
				resources := map[string]workloadinterface.IMetadata{
					"a": deploymentResource("prod", "app", first),
					"b": deploymentResource("prod", "app", second),
					"c": deploymentResource("prod", "app", tt.third),
					"d": deploymentResource("staging", "app", web),
				}
				services := []corev1.Service{
					typedSvc("prod", "web", map[string]string{"app": "web"}),
					typedSvc("prod", "api", map[string]string{"app": "api"}),
					typedSvc("prod", "unmatched", map[string]string{"app": "other"}),
					typedSvc("staging", "staging-web", map[string]string{"app": "web"}),
					typedSvc("prod", "selectorless", nil),
				}
				results := ResolveServiceBackends(services, resources)
				ref := []WorkloadRef{{Namespace: "prod", Kind: "Deployment", Name: "app"}}
				webResult := backendsFor(t, results, "web")
				if tt.unresolved {
					if len(webResult.Backends) != 0 || !reflect.DeepEqual(webResult.UnresolvedBackends, ref) {
						t.Errorf("expected one unresolved identity, got %+v", webResult)
					}
				} else if !reflect.DeepEqual(webResult.Backends, ref) || len(webResult.UnresolvedBackends) != 0 {
					t.Errorf("expected one coalesced backend, got %+v", webResult)
				}
				apiResult := backendsFor(t, results, "api")
				if tt.name == "conflicting" {
					if len(apiResult.Backends) != 0 || !reflect.DeepEqual(apiResult.UnresolvedBackends, ref) {
						t.Errorf("expected ambiguity for second matching variant, got %+v", apiResult)
					}
				} else if len(apiResult.Backends) != 0 || len(apiResult.UnresolvedBackends) != 0 {
					t.Errorf("unexpected api backend: %+v", apiResult)
				}
				for _, svc := range []string{"unmatched", "selectorless"} {
					r := backendsFor(t, results, svc)
					if len(r.Backends) != 0 || len(r.UnresolvedBackends) != 0 {
						t.Errorf("unexpected backend for %s: %+v", svc, r)
					}
				}
				staging := backendsFor(t, results, "staging-web")
				if !reflect.DeepEqual(staging.Backends, []WorkloadRef{{Namespace: "staging", Kind: "Deployment", Name: "app"}}) || len(staging.UnresolvedBackends) != 0 {
					t.Errorf("namespace isolation failed: %+v", staging)
				}
			})
		}
	}
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

func TestResolveServiceBackends_HeadlessAndSelectorlessAreIndependent(t *testing.T) {
	for _, tt := range []struct {
		name         string
		clusterIP    string
		selector     map[string]string
		headless     bool
		selectorless bool
		backends     int
	}{
		{name: "cluster-ip with selector", clusterIP: "10.0.0.1", selector: map[string]string{"app": "web"}, backends: 1},
		{name: "cluster-ip without selector", clusterIP: "10.0.0.1", selectorless: true},
		{name: "headless with selector", clusterIP: corev1.ClusterIPNone, selector: map[string]string{"app": "web"}, headless: true, backends: 1},
		{name: "headless without selector", clusterIP: corev1.ClusterIPNone, headless: true, selectorless: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			svc := typedSvc("prod", "web-svc", tt.selector)
			svc.Spec.ClusterIP = tt.clusterIP
			d := deploymentResource("prod", "web", map[string]any{"app": "web"})

			results := ResolveServiceBackends([]corev1.Service{svc}, makeResources(d))

			r := backendsFor(t, results, "web-svc")
			if r.Headless != tt.headless || r.Selectorless != tt.selectorless {
				t.Errorf("expected Headless=%v, Selectorless=%v, got %+v", tt.headless, tt.selectorless, r)
			}
			if len(r.Backends) != tt.backends {
				t.Fatalf("expected %d backends, got %+v", tt.backends, r.Backends)
			}
			if tt.backends > 0 && r.Backends[0] != (WorkloadRef{Namespace: "prod", Kind: "Deployment", Name: "web"}) {
				t.Errorf("expected matching Deployment backend, got %+v", r.Backends)
			}
		})
	}
}

func TestResolveServiceBackends_ExternalNameIgnoresSelector(t *testing.T) {
	external := typedSvc("prod", "external-svc", map[string]string{"app": "web"})
	external.Spec.Type = corev1.ServiceTypeExternalName
	external.Spec.ExternalName = "example.com"
	local := typedSvc("prod", "local-svc", map[string]string{"app": "web"})
	d := deploymentResource("prod", "web", map[string]any{"app": "web"})

	results := ResolveServiceBackends([]corev1.Service{external, local}, makeResources(d))

	if len(results) != 1 || results[0].ServiceName != "local-svc" {
		t.Fatalf("expected only the local Service, got %+v", results)
	}
	if len(results[0].Backends) != 1 || results[0].Backends[0].Name != "web" {
		t.Errorf("expected local Service to retain its matching backend, got %+v", results[0].Backends)
	}
}

func TestResolveServiceBackends_SelectorMatchesNothingIsNotHeadless(t *testing.T) {
	// A Service WITH a selector that matches no collected workload:
	// Selectorless=false, Backends empty.
	svc := typedSvc("prod", "orphan-svc", map[string]string{"app": "ghost"})
	d := deploymentResource("prod", "web", map[string]any{"app": "web"})

	results := ResolveServiceBackends([]corev1.Service{svc}, makeResources(d))

	r := backendsFor(t, results, "orphan-svc")
	if r.Headless || r.Selectorless {
		t.Error("expected Headless=false and Selectorless=false: ordinary Service with an unmatched selector")
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
