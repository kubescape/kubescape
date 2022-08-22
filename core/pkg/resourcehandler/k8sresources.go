package resourcehandler

import (
	"context"
	"fmt"
	"strings"

	"github.com/armosec/kubescape/v2/core/cautils"
	"github.com/armosec/kubescape/v2/core/pkg/hostsensorutils"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling/apis"

	"github.com/kubescape/k8s-interface/cloudsupport"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"

	"github.com/armosec/armoapi-go/armotypes"

	v1 "k8s.io/api/core/v1"
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
	registryAdaptors  *RegistryAdaptors
}

func NewK8sResourceHandler(k8s *k8sinterface.KubernetesApi, fieldSelector IFieldSelector, hostSensorHandler hostsensorutils.IHostSensor, rbacObjects *cautils.RBACObjects, registryAdaptors *RegistryAdaptors) *K8sResourceHandler {
	return &K8sResourceHandler{
		k8s:               k8s,
		fieldSelector:     fieldSelector,
		hostSensorHandler: hostSensorHandler,
		rbacObjectsAPI:    rbacObjects,
		registryAdaptors:  registryAdaptors,
	}
}

func (k8sHandler *K8sResourceHandler) GetResources(sessionObj *cautils.OPASessionObj, designator *armotypes.PortalDesignator) (*cautils.K8SResources, map[string]workloadinterface.IMetadata, *cautils.KSResources, error) {
	allResources := map[string]workloadinterface.IMetadata{}

	// get k8s resources
	logger.L().Info("Accessing Kubernetes objects")

	cautils.StartSpinner()
	resourceToControl := make(map[string][]string)
	// build resources map
	// map resources based on framework required resources: map["/group/version/kind"][]<k8s workloads ids>
	k8sResourcesMap := setK8sResourceMap(sessionObj.Policies)

	// get namespace and labels from designator (ignore cluster labels)
	_, namespace, labels := armotypes.DigestPortalDesignator(designator)

	// pull k8s recourses
	ksResourceMap := setKSResourceMap(sessionObj.Policies, resourceToControl)

	// map of Kubescape resources to control_ids
	sessionObj.ResourceToControlsMap = resourceToControl

	if err := k8sHandler.pullResources(k8sResourcesMap, allResources, namespace, labels); err != nil {
		cautils.StopSpinner()
		return k8sResourcesMap, allResources, ksResourceMap, err
	}

	numberOfWorkerNodes, err := k8sHandler.pullWorkerNodesNumber()

	if err != nil {
		logger.L().Debug("failed to collect worker nodes number", helpers.Error(err))
	} else {
		if sessionObj.Metadata != nil && sessionObj.Metadata.ContextMetadata.ClusterContextMetadata != nil {
			sessionObj.Metadata.ContextMetadata.ClusterContextMetadata.NumberOfWorkerNodes = numberOfWorkerNodes
		}
	}

	imgVulnResources := cautils.MapImageVulnResources(ksResourceMap)
	// check that controls use image vulnerability resources
	if len(imgVulnResources) > 0 {
		if err := k8sHandler.registryAdaptors.collectImagesVulnerabilities(k8sResourcesMap, allResources, ksResourceMap); err != nil {
			logger.L().Warning("failed to collect image vulnerabilities", helpers.Error(err))
			cautils.SetInfoMapForResources(fmt.Sprintf("failed to pull image scanning data: %s. for more information: https://hub.armosec.io/docs/configuration-of-image-vulnerabilities", err.Error()), imgVulnResources, sessionObj.InfoMap)
		} else {
			if isEmptyImgVulns(*ksResourceMap) {
				cautils.SetInfoMapForResources("image scanning is not configured. for more information: https://hub.armosec.io/docs/configuration-of-image-vulnerabilities", imgVulnResources, sessionObj.InfoMap)
			}
		}
	}

	hostResources := cautils.MapHostResources(ksResourceMap)
	// check that controls use host sensor resources
	if len(hostResources) > 0 {
		if sessionObj.Metadata.ScanMetadata.HostScanner {
			infoMap, err := k8sHandler.collectHostResources(allResources, ksResourceMap)
			if err != nil {
				logger.L().Warning("failed to collect host scanner resources", helpers.Error(err))
				cautils.SetInfoMapForResources(err.Error(), hostResources, sessionObj.InfoMap)
			} else if k8sHandler.hostSensorHandler == nil {
				// using hostSensor mock
				cautils.SetInfoMapForResources("failed to init host scanner", hostResources, sessionObj.InfoMap)
			} else {
				sessionObj.InfoMap = infoMap
			}
		} else {
			cautils.SetInfoMapForResources("enable-host-scan flag not used. For more information: https://hub.armosec.io/docs/host-sensor", hostResources, sessionObj.InfoMap)
		}
	}

	if err := k8sHandler.collectRbacResources(allResources); err != nil {
		logger.L().Warning("failed to collect rbac resources", helpers.Error(err))
	}

	cloudResources := cautils.MapCloudResources(ksResourceMap)

	setMapNamespaceToNumOfResources(allResources, sessionObj)

	// check that controls use cloud resources
	if len(cloudResources) > 0 {
		provider, err := getCloudProviderDescription(allResources, ksResourceMap)
		if err != nil {
			cautils.SetInfoMapForResources(err.Error(), cloudResources, sessionObj.InfoMap)
			logger.L().Warning("failed to collect cloud data", helpers.Error(err))
		}
		if provider != "" {
			if sessionObj.Metadata != nil && sessionObj.Metadata.ContextMetadata.ClusterContextMetadata != nil {
				sessionObj.Metadata.ContextMetadata.ClusterContextMetadata.CloudProvider = provider
			}
		}
	}

	cautils.StopSpinner()
	logger.L().Success("Accessed to Kubernetes objects")

	return k8sResourcesMap, allResources, ksResourceMap, nil
}

func (k8sHandler *K8sResourceHandler) GetClusterAPIServerInfo() *version.Info {
	clusterAPIServerInfo, err := k8sHandler.k8s.DiscoveryClient.ServerVersion()
	if err != nil {
		logger.L().Error("failed to discover API server information", helpers.Error(err))
		return nil
	}
	return clusterAPIServerInfo
}

// set  namespaceToNumOfResources map in report
func setMapNamespaceToNumOfResources(allResources map[string]workloadinterface.IMetadata, sessionObj *cautils.OPASessionObj) {

	if sessionObj.Metadata.ContextMetadata.ClusterContextMetadata.MapNamespaceToNumberOfResources == nil {
		sessionObj.Metadata.ContextMetadata.ClusterContextMetadata.MapNamespaceToNumberOfResources = make(map[string]int)
	}
	for _, resource := range allResources {
		if obj := workloadinterface.NewWorkloadObj(resource.GetObject()); obj != nil {
			ownerReferences, err := obj.GetOwnerReferences()
			if err == nil {
				// if object is highest level and belong to namespace (except Job), add to map
				if len(ownerReferences) == 0 {
					if obj.GetKind() != "Job" {
						if ns := resource.GetNamespace(); ns != "" {
							sessionObj.Metadata.ContextMetadata.ClusterContextMetadata.MapNamespaceToNumberOfResources[ns]++
						}
					}
				}
			} else {
				logger.L().Error("failed to get owner references", helpers.Error(err))
			}
		}
	}
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
					errs = fmt.Errorf("%s; %s", errs, err.Error())
				}
			}
			continue
		}
		// store result as []map[string]interface{}
		metaObjs := ConvertMapListToMeta(k8sinterface.ConvertUnstructuredSliceToMap(result))
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

func (k8sHandler *K8sResourceHandler) collectHostResources(allResources map[string]workloadinterface.IMetadata, ksResourceMap *cautils.KSResources) (map[string]apis.StatusInfo, error) {
	logger.L().Debug("Collecting host scanner resources")
	hostResources, infoMap, err := k8sHandler.hostSensorHandler.CollectResources()
	if err != nil {
		return nil, err
	}

	for rscIdx := range hostResources {
		group, version := getGroupNVersion(hostResources[rscIdx].GetApiVersion())
		groupResource := k8sinterface.JoinResourceTriplets(group, version, hostResources[rscIdx].GetKind())
		allResources[hostResources[rscIdx].GetID()] = &hostResources[rscIdx]

		grpResourceList, ok := (*ksResourceMap)[groupResource]
		if !ok {
			grpResourceList = make([]string, 0)
		}
		(*ksResourceMap)[groupResource] = append(grpResourceList, hostResources[rscIdx].GetID())
	}
	return infoMap, nil
}

func (k8sHandler *K8sResourceHandler) collectRbacResources(allResources map[string]workloadinterface.IMetadata) error {
	logger.L().Debug("Collecting rbac resources")

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

func getCloudProviderDescription(allResources map[string]workloadinterface.IMetadata, ksResourceMap *cautils.KSResources) (string, error) {
	logger.L().Debug("Collecting cloud data")

	clusterName := cautils.ClusterName

	provider := cloudsupport.GetCloudProvider(clusterName)

	if provider != "" {
		logger.L().Debug("cloud", helpers.String("cluster", clusterName), helpers.String("clusterName", clusterName), helpers.String("provider", provider))

		wl, err := cloudsupport.GetDescriptiveInfoFromCloudProvider(clusterName, provider)
		if err != nil {
			// Return error with useful info on how to configure credentials for getting cloud provider info
			logger.L().Debug("failed to get descriptive information", helpers.Error(err))
			return provider, fmt.Errorf("failed to get %s descriptive information. Read more: https://hub.armosec.io/docs/kubescape-integration-with-cloud-providers", strings.ToUpper(provider))
		}
		allResources[wl.GetID()] = wl
		(*ksResourceMap)[fmt.Sprintf("%s/%s", wl.GetApiVersion(), wl.GetKind())] = []string{wl.GetID()}
	}
	return provider, nil

}

func (k8sHandler *K8sResourceHandler) pullWorkerNodesNumber() (int, error) {
	nodesList, err := k8sHandler.k8s.KubernetesClient.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	scheduableNodes := v1.NodeList{}
	if nodesList != nil {
		for _, node := range nodesList.Items {
			if len(node.Spec.Taints) == 0 {
				scheduableNodes.Items = append(scheduableNodes.Items, node)
			} else {
				if !isMasterNodeTaints(node.Spec.Taints) {
					scheduableNodes.Items = append(scheduableNodes.Items, node)
				}
			}
		}
	}
	if err != nil {
		return 0, err
	}
	return len(scheduableNodes.Items), nil
}

// NoSchedule taint with empty value is usually applied to controlplane
func isMasterNodeTaints(taints []v1.Taint) bool {
	for _, taint := range taints {
		if taint.Effect == v1.TaintEffectNoSchedule && taint.Value == "" {
			return true
		}
	}
	return false
}
