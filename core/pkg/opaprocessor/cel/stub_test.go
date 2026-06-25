package cel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	assert.Equal(t, operationCreate, req["operation"])
	assert.Equal(t, "nginx", req["name"])
	assert.Equal(t, "production", req["namespace"])
	// dryRun models a real CREATE, not a dry run.
	assert.Equal(t, false, req["dryRun"])

	// userInfo must exist but carry no identity.
	userInfo, ok := req["userInfo"].(map[string]any)
	require.True(t, ok, "userInfo should be a map")
	assert.Equal(t, "", userInfo["username"])
	assert.Empty(t, userInfo["groups"])

	// kind is a GroupVersionKind; core-group resources have an empty group.
	kind, ok := req["kind"].(map[string]any)
	require.True(t, ok, "kind should be a map")
	assert.Equal(t, "", kind["group"])
	assert.Equal(t, "v1", kind["version"])
	assert.Equal(t, "Pod", kind["kind"])
}

// TestStubRequestHasFullAdmissionRequestShape guards the blocker matthyx
// flagged: because request is cel.DynType, any AdmissionRequest field a VAP
// selects must exist on the stub or evaluation errors offline while passing at
// admission. Keep this aligned with apiserver's BuildRequestType field set.
func TestStubRequestHasFullAdmissionRequestShape(t *testing.T) {
	req := stubRequest(namespacedPod())

	for _, key := range []string{
		"uid", "kind", "resource", "subResource", "requestKind", "requestResource",
		"requestSubResource", "name", "namespace", "operation", "userInfo",
		"dryRun", "options",
	} {
		_, ok := req[key]
		assert.Truef(t, ok, "request is missing field %q", key)
	}

	// resource is a GroupVersionResource: group/version are real, the plural
	// resource name is the zero value (can't resolve a GVR plural offline).
	resource, ok := req["resource"].(map[string]any)
	require.True(t, ok, "resource should be a map")
	assert.Equal(t, "", resource["group"])
	assert.Equal(t, "v1", resource["version"])
	assert.Equal(t, "", resource["resource"])
}

func TestStubRequestGroupedAPIVersion(t *testing.T) {
	req := stubRequest(clusterScopedRole())
	kind := req["kind"].(map[string]any)
	assert.Equal(t, "rbac.authorization.k8s.io", kind["group"])
	assert.Equal(t, "v1", kind["version"])
}

// TestStubRequestSelectableAgainstEnv is the strongest form of the
// full-shape guarantee: it compiles and evaluates selections into every
// request field against the real env. A missing key would surface here as an
// eval error, exactly the offline/admission mismatch we are avoiding.
func TestStubRequestSelectableAgainstEnv(t *testing.T) {
	env, err := newEnv()
	require.NoError(t, err)

	activation := map[string]any{"request": stubRequest(namespacedPod())}

	exprs := []string{
		"request.operation == 'CREATE'",
		"request.name == 'nginx'",
		"request.namespace == 'production'",
		"request.uid == ''",
		"request.kind.kind == 'Pod'",
		"request.resource.resource == ''",
		"request.resource.group == ''",
		"request.subResource == ''",
		"request.requestKind.kind == 'Pod'",
		"request.requestResource.version == 'v1'",
		"request.requestSubResource == ''",
		"request.userInfo.username == ''",
		"size(request.userInfo.groups) == 0",
		"request.dryRun == false",
	}

	for _, expr := range exprs {
		ast, issues := env.Compile(expr)
		require.NoErrorf(t, issues.Err(), "compile %q", expr)

		prg, err := env.Program(ast)
		require.NoErrorf(t, err, "program %q", expr)

		out, _, err := prg.Eval(activation)
		require.NoErrorf(t, err, "eval %q", expr)
		assert.Equalf(t, true, out.Value(), "expr %q should be true", expr)
	}
}

func TestStubBindingsOldObjectIsNull(t *testing.T) {
	b := stubBindings(namespacedPod(), nil)

	// oldObject must be present (declared on the env) and null, so a CREATE
	// has the same null oldObject it would have at live admission.
	v, ok := b["oldObject"]
	require.True(t, ok, "oldObject must be present and null")
	assert.Nil(t, v)
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
		require.True(t, ok, "namespaceObject should be the namespace object")
		name, _, _ := unstructured.NestedString(got, "metadata", "name")
		assert.Equal(t, "production", name)
	})

	t.Run("cluster-scoped resource binds null", func(t *testing.T) {
		b := stubBindings(clusterScopedRole(), nsObject)
		assert.Nil(t, b["namespaceObject"])
	})

	t.Run("namespaced resource without a namespace object binds null", func(t *testing.T) {
		b := stubBindings(namespacedPod(), nil)
		assert.Nil(t, b["namespaceObject"])
	})
}
