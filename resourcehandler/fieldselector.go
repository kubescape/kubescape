package resourcehandler

import (
	"fmt"
	"strings"

	"github.com/armosec/k8s-interface/k8sinterface"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type IFieldSelector interface {
	GetNamespacesSelector(*schema.GroupVersionResource) string
}

type EmptySelector struct {
}

func (es *EmptySelector) GetNamespacesSelector(resource *schema.GroupVersionResource) string {
	return ""
}

type ExcludeSelector struct {
	namespace string
}

func NewExcludeSelector(ns string) *ExcludeSelector {
	return &ExcludeSelector{namespace: ns}
}

type IncludeSelector struct {
	namespace string
}

func NewIncludeSelector(ns string) *IncludeSelector {
	return &IncludeSelector{namespace: ns}
}
func (es *ExcludeSelector) GetNamespacesSelector(resource *schema.GroupVersionResource) string {
	return getNamespacesSelector(resource, es.namespace, "!=")
}

func (is *IncludeSelector) GetNamespacesSelector(resource *schema.GroupVersionResource) string {
	return getNamespacesSelector(resource, is.namespace, "==")
}

func getNamespacesSelector(resource *schema.GroupVersionResource, ns, operator string) string {
	fieldSelectors := ""
	fieldSelector := "metadata."
	if resource.Resource == "namespaces" {
		fieldSelector += "name"
	} else if k8sinterface.IsNamespaceScope(resource.Group, resource.Resource) {
		fieldSelector += "namespace"
	} else {
		return ""
	}
	namespacesSlice := strings.Split(ns, ",")
	for _, n := range namespacesSlice {
		fieldSelectors += fmt.Sprintf("%s!=%s,", fieldSelector, n)
	}
	return fieldSelectors

}
func setFieldSelector(listOptions *metav1.ListOptions, resource *schema.GroupVersionResource, excludedNamespaces string) {
	fieldSelector := "metadata."
	if resource.Resource == "namespaces" {
		fieldSelector += "name"
	} else if k8sinterface.IsNamespaceScope(resource.Group, resource.Resource) {
		fieldSelector += "namespace"
	} else {
		return
	}
	excludedNamespacesSlice := strings.Split(excludedNamespaces, ",")
	for _, excludedNamespace := range excludedNamespacesSlice {
		listOptions.FieldSelector += fmt.Sprintf("%s!=%s,", fieldSelector, excludedNamespace)
	}
}
