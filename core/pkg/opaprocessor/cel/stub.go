package cel

import (
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// operationCreate is the admission operation we report offline. Kubescape
// scans files rather than reacting to live API calls, so every resource is
// treated as a fresh CREATE: that is what gives us CREATE-parity with live
// admission (request.operation=CREATE, oldObject=null).
const operationCreate = "CREATE"

// stubBindings returns the activation entries the offline stub layer owns:
// the stubbed request, the null oldObject, and the namespaceObject. PR #6's
// evaluator merges these with the object, params and variables bindings to
// form the full activation for one resource.
//
//   - obj is the K8s resource being scanned (bound to "object" elsewhere).
//   - namespaceObject is the resource's Namespace object, or nil when the
//     scan does not have it. For a cluster-scoped resource it is ignored and
//     namespaceObject binds to null, matching how the apiserver binds it.
//
// oldObject and namespaceObject are bound to nil (CEL null) rather than left
// absent: the variables are declared on the env (see env.go), and a declared
// variable that is missing from the activation would error at eval time
// instead of evaluating as null.
func stubBindings(obj, namespaceObject map[string]any) map[string]any {
	return map[string]any{
		"request":         stubRequest(obj),
		"oldObject":       nil,
		"namespaceObject": stubNamespaceObject(obj, namespaceObject),
	}
}

// stubRequest builds the "request" variable the way Kubernetes would during
// admission of a fresh CREATE. Because Kubescape is scanning files rather
// than reacting to a live API call, operation is always CREATE and userInfo
// is empty.
//
// Known gap (issue #2001): request.userInfo and authorizer cannot be
// populated meaningfully offline. userInfo is present but empty so that
// expressions referencing request.userInfo.* still evaluate; checks that
// depend on the requesting user being known are a documented limitation, not
// a correctness claim.
func stubRequest(obj map[string]any) map[string]any {
	name, _, _ := unstructured.NestedString(obj, "metadata", "name")
	namespace, _, _ := unstructured.NestedString(obj, "metadata", "namespace")
	kind, _, _ := unstructured.NestedString(obj, "kind")
	apiVersion, _, _ := unstructured.NestedString(obj, "apiVersion")
	group, version := splitAPIVersion(apiVersion)

	return map[string]any{
		"operation": operationCreate,
		"name":      name,
		"namespace": namespace,
		// kind is a GroupVersionKind; some VAPs read request.kind.kind.
		"kind": map[string]any{
			"group":   group,
			"version": version,
			"kind":    kind,
		},
		"dryRun": true,
		// Empty UserInfo: present so request.userInfo.* compiles and
		// evaluates, but carries no identity (see the doc note above).
		"userInfo": map[string]any{
			"username": "",
			"uid":      "",
			"groups":   []any{},
			"extra":    map[string]any{},
		},
	}
}

// stubNamespaceObject resolves the value bound to "namespaceObject".
//
// It is the resource's Namespace object for a namespaced resource, and null
// for a cluster-scoped one — matching the apiserver. When the resource is
// namespaced but the scan does not have the Namespace object (namespaceObject
// is nil), it also binds to null; policies that read namespaceObject.* then
// see an absent namespace rather than failing to evaluate.
func stubNamespaceObject(obj, namespaceObject map[string]any) any {
	if !isNamespaced(obj) {
		return nil
	}
	if namespaceObject == nil {
		return nil
	}
	return namespaceObject
}

// isNamespaced reports whether the resource carries a non-empty
// metadata.namespace. Cluster-scoped resources (Namespace, ClusterRole, …)
// have none.
func isNamespaced(obj map[string]any) bool {
	namespace, _, _ := unstructured.NestedString(obj, "metadata", "namespace")
	return namespace != ""
}

// splitAPIVersion splits a K8s apiVersion ("apps/v1", "v1") into its group
// and version. The core group has an empty group string ("v1" -> "", "v1").
func splitAPIVersion(apiVersion string) (group, version string) {
	if i := strings.Index(apiVersion, "/"); i >= 0 {
		return apiVersion[:i], apiVersion[i+1:]
	}
	return "", apiVersion
}
