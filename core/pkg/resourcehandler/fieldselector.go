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
// --include-namespaces / --exclude-namespaces) into a clean slice. Empty
// entries and surrounding whitespace are dropped.
func splitNamespaces(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

type IFieldSelector interface {
	GetNamespacesSelectors(*schema.GroupVersionResource, *bool) []string
	GetClusterScope(*schema.GroupVersionResource) bool
}

type EmptySelector struct {
}

func (es *EmptySelector) GetNamespacesSelectors(resource *schema.GroupVersionResource, namespaced *bool) []string {
	return []string{""} //
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
