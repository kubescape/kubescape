package resourcehandler

import (
	"strings"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	FieldSelectorsSeparator         = ","
	FieldSelectorsEqualsOperator    = "=="
	FieldSelectorsNotEqualsOperator = "!="
)

// splitNamespaces parses a comma-separated namespace list (as passed to
// --include-namespaces / --exclude-namespaces) into a deduplicated slice.
// Empty entries, surrounding whitespace, and duplicate values are dropped.
func splitNamespaces(s string) []string {
	if s == "" {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if v := strings.TrimSpace(p); v != "" {
			if _, exists := seen[v]; !exists {
				seen[v] = struct{}{}
				out = append(out, v)
			}
		}
	}
	return out
}

type IFieldSelector interface {
	GetNamespacesSelectors(*schema.GroupVersionResource, *bool) []string
	// GetNamespaceScopedQueries returns the namespaces whose namespaced
	// collection endpoint the scan may address directly for this resource,
	// or nil when collection must stay cluster-scoped. Addressing
	// /apis/<gv>/namespaces/<ns>/<resource> returns the same objects a
	// cluster-scoped LIST filtered by metadata.namespace does, but Kubernetes
	// authorizes it against a namespaced Role rather than requiring a
	// ClusterRole.
	GetNamespaceScopedQueries(*schema.GroupVersionResource, *bool) []string
	GetClusterScope(*schema.GroupVersionResource) bool
}

type EmptySelector struct {
}

func (es *EmptySelector) GetNamespacesSelectors(resource *schema.GroupVersionResource, namespaced *bool) []string {
	return []string{""} //
}

func (es *EmptySelector) GetNamespaceScopedQueries(*schema.GroupVersionResource, *bool) []string {
	return nil
}

func (es *EmptySelector) GetClusterScope(*schema.GroupVersionResource) bool {
	return true
}

type ExcludeSelector struct {
	namespace string
}

func NewExcludeSelector(ns string) *ExcludeSelector {
	return &ExcludeSelector{namespace: ns}
}

func (es *ExcludeSelector) GetClusterScope(resource *schema.GroupVersionResource) bool {
	// for selector, 'namespace' is in Namespaced scope
	return resource.Resource == "namespaces"
}

// GetNamespaceScopedQueries always returns nil: excluding namespaces means
// collecting every other one, which needs the cluster-scoped collection and so
// cannot be expressed as a bounded set of namespaced queries.
func (es *ExcludeSelector) GetNamespaceScopedQueries(*schema.GroupVersionResource, *bool) []string {
	return nil
}

type IncludeSelector struct {
	namespace string
}

func NewIncludeSelector(ns string) *IncludeSelector {
	return &IncludeSelector{namespace: ns}
}

func (is *IncludeSelector) GetClusterScope(resource *schema.GroupVersionResource) bool {
	// for selector, 'namespace' is in Namespaced scope
	return resource.Resource == "namespaces"
}

// GetNamespaceScopedQueries returns the included namespaces when the resource is
// namespaced, so collection can address each namespace's own endpoint. A
// cluster-scoped resource, and the Namespace kind itself (which the include
// selector narrows by metadata.name on a cluster-scoped collection), keep the
// cluster-scoped query and return nil.
func (is *IncludeSelector) GetNamespaceScopedQueries(resource *schema.GroupVersionResource, namespaced *bool) []string {
	if !isNamespacedTarget(resource, namespaced) {
		return nil
	}
	return splitNamespaces(is.namespace)
}

// isNamespacedTarget reports whether resource is served under a namespaced
// endpoint, preferring the scope discovery reported and falling back to
// k8s-interface's static table when it did not, mirroring
// getNamespacesSelectorWithOptionalScope.
func isNamespacedTarget(resource *schema.GroupVersionResource, namespaced *bool) bool {
	if resource.Resource == "namespaces" {
		return false
	}
	if namespaced != nil {
		return *namespaced
	}
	return k8sinterface.IsResourceInNamespaceScope(resource.Resource)
}

func (es *ExcludeSelector) GetNamespacesSelectors(resource *schema.GroupVersionResource, namespaced *bool) []string {
	fieldSelectors := ""
	for n := range strings.SplitSeq(es.namespace, FieldSelectorsSeparator) {
		n = strings.TrimSpace(n)
		if n != "" {
			fieldSelectors = combineFieldSelectors(fieldSelectors, getNamespacesSelectorWithOptionalScope(resource, n, FieldSelectorsNotEqualsOperator, namespaced))
		}
	}
	return []string{fieldSelectors}

}

// GetNamespacesSelectors returns one field selector per query the collection has
// to run for this resource. It never returns an empty slice: pullSingleResource
// runs one query per entry, so no entry means the resource is never listed, and
// a resource that is never listed leaves no failure behind either — the scan
// reports it as collected and empty, and every control over it reads as clean.
func (is *IncludeSelector) GetNamespacesSelectors(resource *schema.GroupVersionResource, namespaced *bool) []string {
	fieldSelectors := []string{}
	for n := range strings.SplitSeq(is.namespace, FieldSelectorsSeparator) {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		sel := getNamespacesSelectorWithOptionalScope(resource, n, FieldSelectorsEqualsOperator, namespaced)
		if sel == "" {
			// Cluster-scoped target: per-namespace filtering is meaningless, so a
			// single unfiltered query suffices. Returning one entry per namespace
			// would cause pullSingleResource to LIST the full cluster-scoped
			// collection N times and append duplicates to k8sResources[gvr].
			return []string{""}
		}
		fieldSelectors = append(fieldSelectors, sel)
	}
	if len(fieldSelectors) == 0 {
		// The value named no namespace, so it narrows nothing; fall back to the
		// unfiltered query rather than dropping the resource.
		return []string{""}
	}
	return fieldSelectors
}

func getNamespacesSelectorWithOptionalScope(resource *schema.GroupVersionResource, ns, operator string, namespaced *bool) string {
	if namespaced == nil {
		return getNamespacesSelector(resource.Resource, ns, operator)
	}
	return getNamespacesSelectorForScope(resource, ns, operator, *namespaced)
}

func getNamespacesSelectorForScope(resource *schema.GroupVersionResource, ns, operator string, namespaced bool) string {
	if ns == "" {
		return ""
	}
	if resource.Resource == "namespaces" {
		return getNameFieldSelectorString(ns, operator)
	}
	if namespaced {
		return getNamespaceFieldSelectorString(ns, operator)
	}
	return ""
}

func getNamespacesSelector(kind, ns, operator string) string {
	if ns == "" {
		return ""
	}

	if kind == "namespaces" || kind == "Namespace" {
		return getNameFieldSelectorString(ns, operator)
	}

	if k8sinterface.IsResourceInNamespaceScope(kind) {
		return getNamespaceFieldSelectorString(ns, operator)
	}

	return ""
}

func getNameFieldSelectorString(resourceName, operator string) string {
	return strings.Join([]string{"metadata.name", resourceName}, operator)
}

func getNamespaceFieldSelectorString(namespace, operator string) string {
	return strings.Join([]string{"metadata.namespace", namespace}, operator)
}

func combineFieldSelectors(selectors ...string) string {
	var nonEmptyStrings []string
	for i := range selectors {
		if selectors[i] != "" {
			nonEmptyStrings = append(nonEmptyStrings, selectors[i])
		}
	}
	return strings.Join(nonEmptyStrings, FieldSelectorsSeparator)
}
