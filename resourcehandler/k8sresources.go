package resourcehandler

import (
	"context"
	"fmt"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/opa-utils/reporthandling"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/k8s-interface/workloadinterface"

	"github.com/armosec/armoapi-go/armotypes"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8slabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/dynamic"
)

type K8sResourceHandler struct {
	k8s           *k8sinterface.KubernetesApi
	fieldSelector IFieldSelector
}

func NewK8sResourceHandler(k8s *k8sinterface.KubernetesApi, fieldSelector IFieldSelector) *K8sResourceHandler {
	return &K8sResourceHandler{
		k8s:           k8s,
		fieldSelector: fieldSelector,
	}
}

func (k8sHandler *K8sResourceHandler) GetResources(frameworks []reporthandling.Framework, designator *armotypes.PortalDesignator) (*cautils.K8SResources, error) {
	// get k8s resources
	cautils.ProgressTextDisplay("Accessing Kubernetes objects")

	// build resources map
	k8sResourcesMap := setResourceMap(frameworks)

	// get namespace and labels from designator (ignore cluster labels)
	_, namespace, labels := armotypes.DigestPortalDesignator(designator)

	// pull k8s recourses
	if err := k8sHandler.pullResources(k8sResourcesMap, namespace, labels); err != nil {
		return k8sResourcesMap, err
	}

	cautils.SuccessTextDisplay("Accessed successfully to Kubernetes objects")
	return k8sResourcesMap, nil
}

func (k8sHandler *K8sResourceHandler) GetClusterAPIServerInfo() *version.Info {
	clusterAPIServerInfo, err := k8sHandler.k8s.DiscoveryClient.ServerVersion()
	if err != nil {
		cautils.ErrorDisplay(fmt.Sprintf("Failed to discover API server information: %v", err))
		return nil
	}
	return clusterAPIServerInfo
}
func (k8sHandler *K8sResourceHandler) pullResources(k8sResources *cautils.K8SResources, namespace string, labels map[string]string) error {

	var errs error
	for groupResource := range *k8sResources {
		apiGroup, apiVersion, resource := k8sinterface.StringToResourceGroup(groupResource)
		gvr := schema.GroupVersionResource{Group: apiGroup, Version: apiVersion, Resource: resource}
		result, err := k8sHandler.pullSingleResource(&gvr, namespace, labels)
		if err != nil {
			// handle error
			if errs == nil {
				errs = err
			} else {
				errs = fmt.Errorf("%s\n%s", errs, err.Error())
			}
		} else {
			// store result as []map[string]interface{}
			(*k8sResources)[groupResource] = ConvertMapListToMeta(k8sinterface.ConvertUnstructuredSliceToMap(k8sinterface.FilterOutOwneredResources(result)))
		}
	}
	return errs
}

func (k8sHandler *K8sResourceHandler) pullSingleResource(resource *schema.GroupVersionResource, namespace string, labels map[string]string) ([]unstructured.Unstructured, error) {

	// set labels
	listOptions := metav1.ListOptions{}

	listOptions.FieldSelector += k8sHandler.fieldSelector.GetNamespacesSelector(resource)

	if len(labels) > 0 {
		set := k8slabels.Set(labels)
		listOptions.LabelSelector = set.AsSelector().String()
	}

	// set dynamic object
	var clientResource dynamic.ResourceInterface
	if namespace != "" && k8sinterface.IsNamespaceScope(resource) {
		clientResource = k8sHandler.k8s.DynamicClient.Resource(*resource).Namespace(namespace)
	} else {
		clientResource = k8sHandler.k8s.DynamicClient.Resource(*resource)
	}

	// list resources
	result, err := clientResource.List(context.Background(), listOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to get resource: %v, namespace: %s, labelSelector: %v, reason: %s", resource, namespace, listOptions.LabelSelector, err.Error())
	}

	return result.Items, nil

}
func ConvertMapListToMeta(resourceMap []map[string]interface{}) []workloadinterface.IMetadata {
	workloads := []workloadinterface.IMetadata{}
	for i := range resourceMap {
		if w := workloadinterface.NewObject(resourceMap[i]); w != nil {
			workloads = append(workloads, w)
		}
	}
	return workloads
}
