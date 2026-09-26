package attackpath

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// boolPtr is a test helper: the Kubernetes API uses *bool for
// automountServiceAccountToken so that unset (nil) is distinguishable
// from explicitly false.
func boolPtr(b bool) *bool { return &b }

// workloadObj builds a Deployment IMetadata with the given pod-spec fields
// set, for ServiceAccount binding tests.
func workloadWithSA(namespace, name, saName string, automount *bool, volumes []any) workloadinterface.IMetadata {
	podSpec := map[string]any{}
	if saName != "" {
		podSpec["serviceAccountName"] = saName
	}
	if automount != nil {
		podSpec["automountServiceAccountToken"] = *automount
	}
	if len(volumes) > 0 {
		podSpec["volumes"] = volumes
	}
	return resource(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": name, "namespace": namespace},
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": name}},
				"spec":     podSpec,
			},
		},
	})
}

// projectedSATokenVolume returns a volume entry that carries a projected
// serviceAccountToken source — simulating an explicitly-requested token
// mount regardless of automountServiceAccountToken settings.
func projectedSATokenVolume() map[string]any {
	return map[string]any{
		"name": "kube-api-access",
		"projected": map[string]any{
			"sources": []any{
				map[string]any{
					"serviceAccountToken": map[string]any{
						"expirationSeconds": 3607,
						"path":              "token",
					},
				},
			},
		},
	}
}

// saIndex is a shorthand to build the automount index from ServiceAccount
// typed objects, the same way production code builds it via
// ServiceAccountAutomountIndex.
func saIndex(sas ...corev1.ServiceAccount) map[string]*bool {
	return ServiceAccountAutomountIndex(sas)
}

func saObj(namespace, name string, automount *bool) corev1.ServiceAccount {
	return corev1.ServiceAccount{
		ObjectMeta:                   metav1.ObjectMeta{Namespace: namespace, Name: name},
		AutomountServiceAccountToken: automount,
	}
}

// resultFor finds the ServiceAccountBinding for a given workload name in
// the results slice. Fails the test if not found.
func resultFor(t *testing.T, results []ServiceAccountBinding, name string) ServiceAccountBinding {
	t.Helper()
	for _, r := range results {
		if r.WorkloadRef.Name == name {
			return r
		}
	}
	t.Fatalf("no binding result found for workload %q", name)
	return ServiceAccountBinding{}
}

// --- ServiceAccountAutomountIndex tests ---

func TestServiceAccountAutomountIndex_NilAutomountStoredAsNilPointer(t *testing.T) {
	idx := saIndex(saObj("prod", "app", nil))
	v, ok := idx["prod/app"]
	if !ok {
		t.Fatal("expected prod/app in index")
	}
	if v != nil {
		t.Errorf("expected nil pointer for SA with no automount field, got %v", *v)
	}
}

func TestServiceAccountAutomountIndex_FalseStoredCorrectly(t *testing.T) {
	idx := saIndex(saObj("prod", "restricted", boolPtr(false)))
	v := idx["prod/restricted"]
	if v == nil || *v != false {
		t.Errorf("expected *false for restricted SA, got %v", v)
	}
}

func TestServiceAccountAutomountIndex_TrueStoredCorrectly(t *testing.T) {
	idx := saIndex(saObj("prod", "permissive", boolPtr(true)))
	v := idx["prod/permissive"]
	if v == nil || *v != true {
		t.Errorf("expected *true for permissive SA, got %v", v)
	}
}

// --- ResolveServiceAccountBindings golden-file cases (proposal §7) ---

func TestResolveServiceAccountBindings_DefaultSAAndKubernetesDefaultMountTrue(t *testing.T) {
	// No serviceAccountName set, no automount anywhere → resolves to
	// "default" SA with TokenMounted=true (the Kubernetes default).
	w := workloadWithSA("prod", "web", "", nil, nil)
	results := ResolveServiceAccountBindings(makeResources(w), saIndex())

	r := resultFor(t, results, "web")
	if r.ServiceAccountName != "default" {
		t.Errorf("expected SA name 'default', got %q", r.ServiceAccountName)
	}
	if !r.TokenMounted {
		t.Error("expected TokenMounted=true when nothing opts out (Kubernetes default)")
	}
}

func TestResolveServiceAccountBindings_PodLevelFalseWins(t *testing.T) {
	// automountServiceAccountToken: false at the pod level → TokenMounted=false,
	// regardless of what the SA says. This is golden-file case 1 from proposal §7.
	w := workloadWithSA("prod", "secure", "my-sa", boolPtr(false), nil)
	results := ResolveServiceAccountBindings(
		makeResources(w),
		saIndex(saObj("prod", "my-sa", boolPtr(true))), // SA says true; pod overrides
	)

	r := resultFor(t, results, "secure")
	if r.TokenMounted {
		t.Error("expected TokenMounted=false: pod-level false must win over SA-level true")
	}
}

func TestResolveServiceAccountBindings_SALevelFalseAppliesWhenPodNotSet(t *testing.T) {
	// No pod-level automount set; SA has automountServiceAccountToken: false
	// → TokenMounted=false. Golden-file case 2 from proposal §7.
	w := workloadWithSA("prod", "worker", "restricted-sa", nil, nil)
	results := ResolveServiceAccountBindings(
		makeResources(w),
		saIndex(saObj("prod", "restricted-sa", boolPtr(false))),
	)

	r := resultFor(t, results, "worker")
	if r.TokenMounted {
		t.Error("expected TokenMounted=false: SA-level false must apply when pod level is unset")
	}
}

func TestResolveServiceAccountBindings_ProjectedTokenVolumeWinsOverPodFalse(t *testing.T) {
	// automountServiceAccountToken: false at the pod level, BUT a projected
	// serviceAccountToken volume is explicitly present → TokenMounted=true.
	// This is the critical golden-file case from proposal §7: the token IS
	// mounted because it was explicitly projected, overriding the automount flag.
	w := workloadWithSA("prod", "explicit", "my-sa", boolPtr(false),
		[]any{projectedSATokenVolume()})
	results := ResolveServiceAccountBindings(makeResources(w), saIndex())

	r := resultFor(t, results, "explicit")
	if !r.TokenMounted {
		t.Error("expected TokenMounted=true: projected serviceAccountToken volume is present, overriding automount=false")
	}
}

func TestResolveServiceAccountBindings_ProjectedTokenVolumeWinsOverSAFalse(t *testing.T) {
	// SA-level automountServiceAccountToken: false, no pod-level override,
	// but a projected volume is present → TokenMounted=true.
	// Complements the pod-level case above; both must hold.
	w := workloadWithSA("prod", "projected-only", "no-mount-sa", nil,
		[]any{projectedSATokenVolume()})
	results := ResolveServiceAccountBindings(
		makeResources(w),
		saIndex(saObj("prod", "no-mount-sa", boolPtr(false))),
	)

	r := resultFor(t, results, "projected-only")
	if !r.TokenMounted {
		t.Error("expected TokenMounted=true: projected volume wins over SA-level automount=false")
	}
}

func TestResolveServiceAccountBindings_ExplicitSANameCarriedThrough(t *testing.T) {
	w := workloadWithSA("prod", "api", "custom-sa", nil, nil)
	results := ResolveServiceAccountBindings(makeResources(w), saIndex())

	r := resultFor(t, results, "api")
	if r.ServiceAccountName != "custom-sa" {
		t.Errorf("expected SA name 'custom-sa', got %q", r.ServiceAccountName)
	}
	if r.Namespace != "prod" {
		t.Errorf("expected Namespace 'prod', got %q", r.Namespace)
	}
}

func TestResolveServiceAccountBindings_NonWorkloadKindIsIgnored(t *testing.T) {
	// A Service in the resource map must be ignored: only kinds in
	// WorkloadKindGVRs produce bindings.
	svc := resource(map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata":   map[string]any{"name": "svc", "namespace": "prod"},
		"spec":       map[string]any{"selector": map[string]any{"app": "web"}},
	})
	results := ResolveServiceAccountBindings(makeResources(svc), saIndex())
	if len(results) != 0 {
		t.Errorf("expected no results for a non-workload kind, got %+v", results)
	}
}

func TestResolveServiceAccountBindings_OutputIsDeterministic(t *testing.T) {
	// Multiple workloads: results must be in resource-ID order on every run.
	a := workloadWithSA("alpha", "app", "sa-a", nil, nil)
	b := workloadWithSA("beta", "app", "sa-b", nil, nil)
	c := workloadWithSA("alpha", "worker", "sa-c", nil, nil)

	first := ResolveServiceAccountBindings(makeResources(a, b, c), saIndex())
	second := ResolveServiceAccountBindings(makeResources(a, b, c), saIndex())

	if len(first) != len(second) {
		t.Fatalf("run lengths differ: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].WorkloadRef != second[i].WorkloadRef {
			t.Errorf("position %d differs between runs: %+v vs %+v", i, first[i].WorkloadRef, second[i].WorkloadRef)
		}
	}
}

func TestResolveServiceAccountBindings_EmptyResourcesReturnsEmpty(t *testing.T) {
	results := ResolveServiceAccountBindings(map[string]workloadinterface.IMetadata{}, saIndex())
	if len(results) != 0 {
		t.Errorf("expected empty result for empty resources, got %+v", results)
	}
}