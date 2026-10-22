package attackpath

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	corev1 "k8s.io/api/core/v1"
)

func TestResolversIgnoreCustomWorkloadKinds(t *testing.T) {
	custom := deploymentResource("prod", "web", map[string]any{"app": "custom"}).GetObject()
	custom["apiVersion"] = "example.com/v1"
	custom["spec"].(map[string]any)["template"].(map[string]any)["spec"] = map[string]any{"containers": []any{map[string]any{"name": "app", "image": "test"}}}
	builtin := workloadWithSA("prod", "web", "real", nil, nil).GetObject()
	builtin["spec"].(map[string]any)["template"].(map[string]any)["metadata"] = map[string]any{"labels": map[string]any{"app": "builtin"}}
	for _, withBuiltin := range []bool{false, true} {
		resources := map[string]workloadinterface.IMetadata{"custom.yaml": resource(custom)}
		if withBuiltin {
			resources["builtin.yaml"] = resource(builtin)
		}
		endpoints := ResolveEndpointsFromResources(resources, []WorkloadRef{{Namespace: "prod", Kind: "Deployment", Name: "web"}})
		if len(endpoints) != 1 || endpoints[0].Resolved != withBuiltin {
			t.Fatalf("builtin=%v endpoints=%+v", withBuiltin, endpoints)
		}
		if withBuiltin && endpoints[0].Endpoint.Labels["app"] != "builtin" {
			t.Fatal("custom resource contaminated endpoint")
		}
		bindings := ResolveServiceAccountBindings(resources, map[string]*bool{"prod/real": nil})
		expected := 0
		if withBuiltin {
			expected = 1
		}
		if len(bindings) != expected {
			t.Fatalf("builtin=%v bindings=%+v", withBuiltin, bindings)
		}
		if withBuiltin && bindings[0].ServiceAccountName != "real" {
			t.Fatal("custom resource created a binding")
		}
		for _, label := range []string{"custom", "builtin"} {
			backends := ResolveServiceBackends([]corev1.Service{typedSvc("prod", "svc", map[string]string{"app": label})}, resources)
			want := 0
			if withBuiltin && label == "builtin" {
				want = 1
			}
			if len(backends) != 1 || len(backends[0].Backends) != want {
				t.Fatalf("builtin=%v label=%s backends=%+v", withBuiltin, label, backends)
			}
		}
	}
}
