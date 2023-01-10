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
			fieldSelectors += getNamespacesSelector(resource, n, "!=") + ","
		}
	}
	return []string{fieldSelectors}

}

func (is *IncludeSelector) GetNamespacesSelectors(resource *schema.GroupVersionResource) []string {
	fieldSelectors := []string{}
	for _, n := range strings.Split(is.namespace, ",") {
		if n != "" {
			fieldSelectors = append(fieldSelectors, getNamespacesSelector(resource, n, "=="))
		}
	}
	return fieldSelectors
}

func getNamespacesSelector(resource *schema.GroupVersionResource, ns, operator string) string {
	fieldSelector := "metadata."
	if resource.Resource == "namespaces" {
		fieldSelector += "name"
	} else if k8sinterface.IsResourceInNamespaceScope(resource.Resource) {
		fieldSelector += "namespace"
	} else {
		return ""
	}
	return fmt.Sprintf("%s%s%s", fieldSelector, operator, ns)

}
