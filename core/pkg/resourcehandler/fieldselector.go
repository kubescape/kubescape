package resourcehandler

import (
	"fmt"
	"strings"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type IFieldSelector interface {
	GetNamespacesSelectors(*schema.GroupVersionResource) []string
	GetClusterScope(*schema.GroupVersionResource) bool
}

type EmptySelector struct {
}

func (es *EmptySelector) GetNamespacesSelectors(resource *schema.GroupVersionResource) []string {
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

func (es *ExcludeSelector) GetNamespacesSelectors(resource *schema.GroupVersionResource) []string {
	fieldSelectors := ""
	for _, n := range strings.Split(es.namespace, ",") {
		if n != "" {
			fieldSelectors = combineFieldSelectors(fieldSelectors, getNamespacesSelector(resource.Resource, n, "!="))
		}
	}
	return []string{fieldSelectors}

}

func (is *IncludeSelector) GetNamespacesSelectors(resource *schema.GroupVersionResource) []string {
	fieldSelectors := []string{}
	for _, n := range strings.Split(is.namespace, ",") {
		if n != "" {
			fieldSelectors = append(fieldSelectors, getNamespacesSelector(resource.Resource, n, "=="))
		}
	}
	return fieldSelectors
}

func getNamespacesSelector(kind, ns, operator string) string {
	if ns == "" {
		return ""
	}

	if kind == "namespaces" || kind == "Namespace" {
		return getNameFieldSelector(ns, operator)
	}

	if k8sinterface.IsResourceInNamespaceScope(kind) {
		return fmt.Sprintf("metadata.namespace%s%s", operator, ns)
	}

	return ""
}

func getNameFieldSelector(resourceName, operator string) string {
	return fmt.Sprintf("metadata.name%s%s", operator, resourceName)
}

func combineFieldSelectors(selectors ...string) string {
	var nonEmptyStrings []string
	for i := range selectors {
		if selectors[i] != "" {
			nonEmptyStrings = append(nonEmptyStrings, selectors[i])
		}
	}
	return strings.Join(nonEmptyStrings, ",")
}
