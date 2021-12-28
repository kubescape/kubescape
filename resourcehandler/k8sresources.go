package resourcehandler

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/hostsensorutils"
	"github.com/armosec/opa-utils/objectsenvelopes"
	"github.com/armosec/opa-utils/reporthandling"

	"github.com/armosec/k8s-interface/cloudsupport"
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
	k8s               *k8sinterface.KubernetesApi
	hostSensorHandler hostsensorutils.IHostSensor
	fieldSelector     IFieldSelector
	rbacObjectsAPI    *cautils.RBACObjects
}

func NewK8sResourceHandler(k8s *k8sinterface.KubernetesApi, fieldSelector IFieldSelector, hostSensorHandler hostsensorutils.IHostSensor, rbacObjects *cautils.RBACObjects) *K8sResourceHandler {
	return &K8sResourceHandler{
		k8s:               k8s,
		fieldSelector:     fieldSelector,
		hostSensorHandler: hostSensorHandler,
		rbacObjectsAPI:    rbacObjects,
	}
}

func (k8sHandler *K8sResourceHandler) GetResources(frameworks []reporthandling.Framework, designator *armotypes.PortalDesignator) (*cautils.K8SResources, map[string]workloadinterface.IMetadata, error) {
	allResources := map[string]workloadinterface.IMetadata{}

	// get k8s resources
	cautils.ProgressTextDisplay("Accessing Kubernetes objects")

	cautils.StartSpinner()

	// build resources map
	// map resources based on framework required resources: map["/group/version/kind"][]<k8s workloads ids>
	k8sResourcesMap := setResourceMap(frameworks)

	// get namespace and labels from designator (ignore cluster labels)
	_, namespace, labels := armotypes.DigestPortalDesignator(designator)

	// pull k8s recourses
	if err := k8sHandler.pullResources(k8sResourcesMap, allResources, namespace, labels); err != nil {
		return k8sResourcesMap, allResources, err
	}
	if err := k8sHandler.collectHostResources(allResources, k8sResourcesMap); err != nil {
		cautils.WarningDisplay(os.Stderr, "Warning: failed to collect host sensor resources\n")
	}

	if err := k8sHandler.collectRbacResources(allResources); err != nil {
		cautils.WarningDisplay(os.Stderr, "Warning: failed to collect rbac resources\n")
	}
	if err := getCloudProviderDescription(allResources, k8sResourcesMap); err != nil {
		cautils.WarningDisplay(os.Stderr, fmt.Sprintf("Warning: %v\n", err.Error()))
	}

	cautils.StopSpinner()

	cautils.SuccessTextDisplay("Accessed successfully to Kubernetes objects")
	return k8sResourcesMap, allResources, nil
}

func (k8sHandler *K8sResourceHandler) GetClusterAPIServerInfo() *version.Info {
	clusterAPIServerInfo, err := k8sHandler.k8s.DiscoveryClient.ServerVersion()
	if err != nil {
		cautils.ErrorDisplay(fmt.Sprintf("Failed to discover API server information: %v", err))
		return nil
	}
	return clusterAPIServerInfo
}

func (k8sHandler *K8sResourceHandler) pullResources(k8sResources *cautils.K8SResources, allResources map[string]workloadinterface.IMetadata, namespace string, labels map[string]string) error {

	var errs error
	for groupResource := range *k8sResources {
		apiGroup, apiVersion, resource := k8sinterface.StringToResourceGroup(groupResource)
		gvr := schema.GroupVersionResource{Group: apiGroup, Version: apiVersion, Resource: resource}
		result, err := k8sHandler.pullSingleResource(&gvr, namespace, labels)
		if err != nil {
			if !strings.Contains(err.Error(), "the server could not find the requested resource") {
				// handle error
				if errs == nil {
					errs = err
				} else {
					errs = fmt.Errorf("%s\n%s", errs, err.Error())
				}
			}
			continue
		}
		// store result as []map[string]interface{}
		metaObjs := ConvertMapListToMeta(k8sinterface.ConvertUnstructuredSliceToMap(k8sinterface.FilterOutOwneredResources(result)))
		for i := range metaObjs {
			allResources[metaObjs[i].GetID()] = metaObjs[i]
		}
		(*k8sResources)[groupResource] = workloadinterface.ListMetaIDs(metaObjs)
	}
	return errs
}

func (k8sHandler *K8sResourceHandler) pullSingleResource(resource *schema.GroupVersionResource, namespace string, labels map[string]string) ([]unstructured.Unstructured, error) {
	resourceList := []unstructured.Unstructured{}
	// set labels
	listOptions := metav1.ListOptions{}
	fieldSelectors := k8sHandler.fieldSelector.GetNamespacesSelectors(resource)
	for i := range fieldSelectors {

		listOptions.FieldSelector = fieldSelectors[i]

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
		if err != nil || result == nil {
			return nil, fmt.Errorf("failed to get resource: %v, namespace: %s, labelSelector: %v, reason: %v", resource, namespace, listOptions.LabelSelector, err)
		}

		resourceList = append(resourceList, result.Items...)

	}

	return resourceList, nil

}
func ConvertMapListToMeta(resourceMap []map[string]interface{}) []workloadinterface.IMetadata {
	workloads := []workloadinterface.IMetadata{}
	for i := range resourceMap {
		if w := objectsenvelopes.NewObject(resourceMap[i]); w != nil {
			workloads = append(workloads, w)
		}
	}
	return workloads
}

func (k8sHandler *K8sResourceHandler) collectHostResources(allResources map[string]workloadinterface.IMetadata, resourcesMap *cautils.K8SResources) error {
	hostResources, err := k8sHandler.hostSensorHandler.CollectResources()
	if err != nil {
		return err
	}
	for rscIdx := range hostResources {
		group, version := getGroupNVersion(hostResources[rscIdx].GetApiVersion())
		groupResource := k8sinterface.JoinResourceTriplets(group, version, hostResources[rscIdx].GetKind())
		allResources[hostResources[rscIdx].GetID()] = &hostResources[rscIdx]

		grpResourceList, ok := (*resourcesMap)[groupResource]
		if !ok {
			grpResourceList = make([]string, 0)
		}
		(*resourcesMap)[groupResource] = append(grpResourceList, hostResources[rscIdx].GetID())
	}
	return nil
}

func (k8sHandler *K8sResourceHandler) collectRbacResources(allResources map[string]workloadinterface.IMetadata) error {
	if k8sHandler.rbacObjectsAPI == nil {
		return nil
	}
	allRbacResources, err := k8sHandler.rbacObjectsAPI.ListAllResources()
	if err != nil {
		return err
	}
	for k, v := range allRbacResources {
		allResources[k] = v
	}
	return nil
}

func getCloudProviderDescription(allResources map[string]workloadinterface.IMetadata, k8sResourcesMap *cautils.K8SResources) error {
	if cloudsupport.IsRunningInCloudProvider() {
		wl, err := cloudsupport.GetDescriptiveInfoFromCloudProvider()
		if err != nil {
			cluster := k8sinterface.GetCurrentContext().Cluster
			provider := cloudsupport.GetCloudProvider(cluster)
			// Return error with useful info on how to configure credentials for getting cloud provider info
			switch provider {
			case "gke":
				return fmt.Errorf("could not get descriptive information about gke cluster: %s using sdk client. See https://developers.google.com/accounts/docs/application-default-credentials for more information", cluster)
			case "eks":
				return fmt.Errorf("could not get descriptive information about eks cluster: %s using sdk client. Check out how to configure credentials in https://docs.aws.amazon.com/sdk-for-go/api/", cluster)
			case "aks":
				return fmt.Errorf("could not get descriptive information about aks cluster: %s. %v", cluster, err.Error())
			}
			return err
		}
		allResources[wl.GetID()] = wl
		(*k8sResourcesMap)[fmt.Sprintf("%s/%s", wl.GetApiVersion(), wl.GetKind())] = []string{wl.GetID()}
	}
	return nil

}
