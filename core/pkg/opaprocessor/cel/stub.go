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
// The whole AdmissionRequest shape is populated, not just the fields we have
// real values for. request is declared cel.DynType on the env, so selecting a
// key that is absent from this map is a runtime error rather than null. At
// live admission every one of these fields is set, so a VAP reading e.g.
// request.resource.resource passes on a cluster but would error offline if we
// left the key out. So every field a real AdmissionRequest exposes is present
// here, with a zero value where we have nothing real, so any field a policy
// selects resolves instead of blowing up at eval time: kind, resource,
// subResource, requestKind, requestResource, requestSubResource, name,
// namespace, operation, userInfo, dryRun, options, uid.
//
// Known gaps (issue #2001), present-but-zero so selection never errors:
//   - userInfo carries no identity (offline we don't know the requester), so
//     checks depending on the requesting user are a documented limitation.
//   - resource/requestResource carry the group and version but an empty
//     resource (plural) name: resolving the GVR plural offline needs a
//     RESTMapper we don't have, so it stays the zero value.
func stubRequest(obj map[string]any) map[string]any {
	name, _, _ := unstructured.NestedString(obj, "metadata", "name")
	namespace, _, _ := unstructured.NestedString(obj, "metadata", "namespace")
	kind, _, _ := unstructured.NestedString(obj, "kind")
	apiVersion, _, _ := unstructured.NestedString(obj, "apiVersion")
	group, version := splitAPIVersion(apiVersion)

	// kind is a GroupVersionKind; resource is a GroupVersionResource. They
	// share group/version. requestKind/requestResource equal kind/resource
	// when no API conversion is involved, which is always the case offline.
	gvk := map[string]any{"group": group, "version": version, "kind": kind}
	gvr := map[string]any{"group": group, "version": version, "resource": ""}

	return map[string]any{
		"uid":                "",
		"kind":               gvk,
		"resource":           gvr,
		"subResource":        "",
		"requestKind":        gvk,
		"requestResource":    gvr,
		"requestSubResource": "",
		"name":               name,
		"namespace":          namespace,
		"operation":          operationCreate,
		// Empty UserInfo: present so request.userInfo.* evaluates, but
		// carries no identity (see the doc note above).
		"userInfo": map[string]any{
			"username": "",
			"uid":      "",
			"groups":   []any{},
			"extra":    map[string]any{},
		},
		// dryRun is false: we model a real CREATE (e.g. kubectl apply), which
		// is the case the scan/admission parity claim is about. A policy that
		// gates on request.dryRun then sees what it would at a real admission.
		"dryRun":  false,
		"options": map[string]any{},
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
