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
	for _, n := range strings.Split(es.namespace, FieldSelectorsSeparator) {
		if n != "" {
			fieldSelectors = combineFieldSelectors(fieldSelectors, getNamespacesSelector(resource.Resource, n, FieldSelectorsNotEqualsOperator))
		}
	}
	return []string{fieldSelectors}

}

func (is *IncludeSelector) GetNamespacesSelectors(resource *schema.GroupVersionResource) []string {
	fieldSelectors := []string{}
	for _, n := range strings.Split(is.namespace, FieldSelectorsSeparator) {
		if n != "" {
			fieldSelectors = append(fieldSelectors, getNamespacesSelector(resource.Resource, n, FieldSelectorsEqualsOperator))
		}
	}
	return fieldSelectors
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
