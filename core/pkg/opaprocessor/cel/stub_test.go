package cel

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func namespacedPod() map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "nginx",
			"namespace": "production",
		},
	}
}

func clusterScopedRole() map[string]any {
	return map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata": map[string]any{
			"name": "view",
		},
	}
}

func TestStubRequest(t *testing.T) {
	req := stubRequest(namespacedPod())

	if got := req["operation"]; got != operationCreate {
		t.Errorf("operation = %v, want %q", got, operationCreate)
	}
	if got := req["name"]; got != "nginx" {
		t.Errorf("name = %v, want %q", got, "nginx")
	}
	if got := req["namespace"]; got != "production" {
		t.Errorf("namespace = %v, want %q", got, "production")
	}

	// userInfo must exist but carry no identity.
	userInfo, ok := req["userInfo"].(map[string]any)
	if !ok {
		t.Fatalf("userInfo is %T, want map[string]any", req["userInfo"])
	}
	if got := userInfo["username"]; got != "" {
		t.Errorf("userInfo.username = %v, want empty", got)
	}
	if groups, ok := userInfo["groups"].([]any); !ok || len(groups) != 0 {
		t.Errorf("userInfo.groups = %v, want empty slice", userInfo["groups"])
	}

	// kind is a GroupVersionKind; core-group resources have an empty group.
	kind, ok := req["kind"].(map[string]any)
	if !ok {
		t.Fatalf("kind is %T, want map[string]any", req["kind"])
	}
	if got := kind["group"]; got != "" {
		t.Errorf("kind.group = %v, want empty (core group)", got)
	}
	if got := kind["version"]; got != "v1" {
		t.Errorf("kind.version = %v, want %q", got, "v1")
	}
	if got := kind["kind"]; got != "Pod" {
		t.Errorf("kind.kind = %v, want %q", got, "Pod")
	}
}

func TestStubRequestGroupedAPIVersion(t *testing.T) {
	req := stubRequest(clusterScopedRole())
	kind := req["kind"].(map[string]any)
	if got := kind["group"]; got != "rbac.authorization.k8s.io" {
		t.Errorf("kind.group = %v, want %q", got, "rbac.authorization.k8s.io")
	}
	if got := kind["version"]; got != "v1" {
		t.Errorf("kind.version = %v, want %q", got, "v1")
	}
}

func TestStubBindingsOldObjectIsNull(t *testing.T) {
	b := stubBindings(namespacedPod(), nil)

	// oldObject must be present (declared on the env) and null, so a CREATE
	// has the same null oldObject it would have at live admission.
	v, ok := b["oldObject"]
	if !ok {
		t.Fatal("oldObject missing from bindings; must be present and null")
	}
	if v != nil {
		t.Errorf("oldObject = %v, want nil (null)", v)
	}
}

func TestStubBindingsNamespaceObject(t *testing.T) {
	nsObject := map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata": map[string]any{
			"name":   "production",
			"labels": map[string]any{"team": "payments"},
		},
	}

	t.Run("namespaced resource binds the namespace object", func(t *testing.T) {
		b := stubBindings(namespacedPod(), nsObject)
		got, ok := b["namespaceObject"].(map[string]any)
		if !ok {
			t.Fatalf("namespaceObject is %T, want the namespace object", b["namespaceObject"])
		}
		name, _, _ := unstructured.NestedString(got, "metadata", "name")
		if name != "production" {
			t.Errorf("namespaceObject.metadata.name = %q, want %q", name, "production")
		}
	})

	t.Run("cluster-scoped resource binds null", func(t *testing.T) {
		b := stubBindings(clusterScopedRole(), nsObject)
		if got := b["namespaceObject"]; got != nil {
			t.Errorf("namespaceObject = %v, want nil for cluster-scoped resource", got)
		}
	})

	t.Run("namespaced resource without a namespace object binds null", func(t *testing.T) {
		b := stubBindings(namespacedPod(), nil)
		if got := b["namespaceObject"]; got != nil {
			t.Errorf("namespaceObject = %v, want nil when the scan lacks it", got)
		}
	})
}
