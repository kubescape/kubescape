package networkpolicy

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
)

func TestFromResources_ExtractsPoliciesAndNamespacesOnly(t *testing.T) {
	np := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
		"metadata":   map[string]any{"name": "deny-all", "namespace": "prod"},
		"spec": map[string]any{
			"podSelector": map[string]any{},
			"policyTypes": []any{"Ingress"},
		},
	})
	ns := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata":   map[string]any{"name": "prod", "labels": map[string]any{"env": "prod"}},
	})
	pod := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "app", "namespace": "prod"},
	})

	resources := map[string]workloadinterface.IMetadata{
		np.GetID():  np,
		ns.GetID():  ns,
		pod.GetID(): pod,
	}

	policies, namespaces, errs := FromResources(resources)

	if len(errs) != 0 {
		t.Fatalf("unexpected decode errors: %v", errs)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	if policies[0].Name != "deny-all" || policies[0].Namespace != "prod" {
		t.Errorf("unexpected policy identity: %+v", policies[0].ObjectMeta)
	}
	if len(policies[0].Spec.PolicyTypes) != 1 || policies[0].Spec.PolicyTypes[0] != "Ingress" {
		t.Errorf("policyTypes did not decode correctly: %+v", policies[0].Spec.PolicyTypes)
	}

	if len(namespaces) != 1 {
		t.Fatalf("expected 1 namespace, got %d", len(namespaces))
	}
	if namespaces[0].Name != "prod" || namespaces[0].Labels["env"] != "prod" {
		t.Errorf("unexpected namespace info: %+v", namespaces[0])
	}

	// The Pod must contribute neither a policy nor a namespace entry.
}

func TestFromResources_MalformedNetworkPolicyIsSkippedNotFatal(t *testing.T) {
	good := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
		"metadata":   map[string]any{"name": "good", "namespace": "ns"},
		"spec":       map[string]any{"podSelector": map[string]any{}},
	})
	bad := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
		"metadata":   map[string]any{"name": "bad", "namespace": "ns"},
		// policyTypes must be a list of strings; this value cannot decode
		// into []networkingv1.PolicyType.
		"spec": map[string]any{"podSelector": map[string]any{}, "policyTypes": 12345},
	})

	resources := map[string]workloadinterface.IMetadata{
		good.GetID(): good,
		bad.GetID():  bad,
	}

	policies, _, errs := FromResources(resources)

	if len(policies) != 1 {
		t.Fatalf("expected the well-formed policy to still decode, got %d policies", len(policies))
	}
	if len(errs) != 1 {
		t.Fatalf("expected exactly one decode error for the malformed policy, got %d", len(errs))
	}
}

func TestEndpointFromResource_CarriesNamespaceNameAndLabels(t *testing.T) {
	pod := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "web",
			"namespace": "prod",
			"labels":    map[string]any{"app": "web"},
		},
	})

	ep := EndpointFromResource(pod)

	if ep.Namespace != "prod" || ep.Name != "web" {
		t.Errorf("unexpected endpoint identity: %+v", ep)
	}
	if ep.Labels["app"] != "web" {
		t.Errorf("expected labels to carry through, got %+v", ep.Labels)
	}
}

func TestEndpointFromResource_NilResourceIsSafe(t *testing.T) {
	ep := EndpointFromResource(nil)
	if ep.Namespace != "" || ep.Name != "" || ep.Labels != nil {
		t.Errorf("expected a zero-value Endpoint for a nil resource, got %+v", ep)
	}
}

// When several policies admit the same connection, the Decision names the
// first one in resource-ID order, so the same snapshot names the same policy
// on every run instead of whichever one map iteration happens to yield first.
func TestFromResources_MatchedPolicyIsTheSameOnEveryRun(t *testing.T) {
	resources := map[string]workloadinterface.IMetadata{}
	for _, name := range []string{"allow-a", "allow-b", "allow-c", "allow-d"} {
		np := workloadinterface.NewWorkloadObj(map[string]any{
			"apiVersion": "networking.k8s.io/v1",
			"kind":       "NetworkPolicy",
			"metadata":   map[string]any{"name": name, "namespace": "prod"},
			"spec": map[string]any{
				"podSelector": map[string]any{},
				"policyTypes": []any{"Ingress"},
				"ingress":     []any{map[string]any{}},
			},
		})
		resources[np.GetID()] = np
	}
	src := Endpoint{Namespace: "prod", Name: "client", Labels: map[string]string{"app": "client"}}
	dst := Endpoint{Namespace: "prod", Name: "server", Labels: map[string]string{"app": "server"}}

	for run := 0; run < 50; run++ {
		policies, namespaces, errs := FromResources(resources)
		if len(errs) != 0 {
			t.Fatalf("unexpected decode errors: %v", errs)
		}
		idx, _ := NewIndex(policies, namespaces)
		_, _, ingress := idx.Reaches(src, dst, nil)
		if ingress.MatchedPolicy != "prod/allow-a" {
			t.Fatalf("run %d: ingress MatchedPolicy = %q, want %q (the first admitting policy by resource ID)", run, ingress.MatchedPolicy, "prod/allow-a")
		}
	}
}
