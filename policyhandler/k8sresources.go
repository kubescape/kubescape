package policyhandler

import (
	"fmt"
	"strings"

	"github.com/armosec/kubescape/cautils"

	"github.com/armosec/k8s-interface/k8sinterface"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/opapolicy"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8slabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

const SelectAllResources = "*"

func (policyHandler *PolicyHandler) getK8sResources(frameworks []opapolicy.Framework, designator *armotypes.PortalDesignator, excludedNamespaces string) (*cautils.K8SResources, error) {
	// get k8s resources
	cautils.ProgressTextDisplay("Accessing Kubernetes objects")

	// build resources map
	k8sResourcesMap := setResourceMap(frameworks)

	// get namespace and labels from designator (ignore cluster labels)
	_, namespace, labels := armotypes.DigestPortalDesignator(designator)

	// pull k8s recourses
	if err := policyHandler.pullResources(k8sResourcesMap, namespace, labels, excludedNamespaces); err != nil {
		return k8sResourcesMap, err
	}

	cautils.SuccessTextDisplay("Accessed successfully to Kubernetes objects, let’s start!!!")
	return k8sResourcesMap, nil
}

func (policyHandler *PolicyHandler) pullResources(k8sResources *cautils.K8SResources, namespace string, labels map[string]string, excludedNamespaces string) error {

	var errs error
	for groupResource := range *k8sResources {
		apiGroup, apiVersion, resource := k8sinterface.StringToResourceGroup(groupResource)
		gvr := schema.GroupVersionResource{Group: apiGroup, Version: apiVersion, Resource: resource}
		result, err := policyHandler.pullSingleResource(&gvr, namespace, labels, excludedNamespaces)
		if err != nil {
			// handle error
			if errs == nil {
				errs = err
			} else {
				errs = fmt.Errorf("%s\n%s", errs, err.Error())
			}
		} else {
			// store result as []map[string]interface{}
			(*k8sResources)[groupResource] = k8sinterface.ConvertUnstructuredSliceToMap(k8sinterface.FilterOutOwneredResources(result))
		}
	}
	return errs
}

func (policyHandler *PolicyHandler) pullSingleResource(resource *schema.GroupVersionResource, namespace string, labels map[string]string, excludedNamespaces string) ([]unstructured.Unstructured, error) {

	// set labels
	listOptions := metav1.ListOptions{}
	if excludedNamespaces != "" {
		setFieldSelector(&listOptions, resource, excludedNamespaces)
	}
	if len(labels) > 0 {
		set := k8slabels.Set(labels)
		listOptions.LabelSelector = set.AsSelector().String()
	}

	// set dynamic object
	var clientResource dynamic.ResourceInterface
	if namespace != "" && k8sinterface.IsNamespaceScope(resource.Group, resource.Resource) {
		clientResource = policyHandler.k8s.DynamicClient.Resource(*resource).Namespace(namespace)
	} else {
		clientResource = policyHandler.k8s.DynamicClient.Resource(*resource)
	}

	// list resources
	result, err := clientResource.List(policyHandler.k8s.Context, listOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to get resource: %v, namespace: %s, labelSelector: %v, reason: %s", resource, namespace, listOptions.LabelSelector, err.Error())
	}

	return result.Items, nil

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
