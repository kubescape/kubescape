package resourcehandler

import (
	"context"
	"fmt"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/hostsensorutils"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling/apis"

	"github.com/kubescape/k8s-interface/cloudsupport"
	cloudapis "github.com/kubescape/k8s-interface/cloudsupport/apis"
	cloudv1 "github.com/kubescape/k8s-interface/cloudsupport/v1"
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

type cloudResourceGetter func(string, string) (workloadinterface.IMetadata, error)

var cloudResourceGetterMapping = map[string]cloudResourceGetter{
	cloudapis.CloudProviderDescribeKind:                cloudsupport.GetDescriptiveInfoFromCloudProvider,
	cloudapis.CloudProviderDescribeRepositoriesKind:    cloudsupport.GetDescribeRepositoriesFromCloudProvider,
	cloudapis.CloudProviderListEntitiesForPoliciesKind: cloudsupport.GetListEntitiesForPoliciesFromCloudProvider,
}

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

func (k8sHandler *K8sResourceHandler) GetResources(ctx context.Context, sessionObj *cautils.OPASessionObj, designator *armotypes.PortalDesignator) (*cautils.K8SResources, map[string]workloadinterface.IMetadata, *cautils.KSResources, error) {
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
		sessionObj.SetNumberOfWorkerNodes(numberOfWorkerNodes)
	}

	cautils.StopSpinner()
	logger.L().Success("Accessed to Kubernetes objects")

	imgVulnResources := cautils.MapImageVulnResources(ksResourceMap)
	// check that controls use image vulnerability resources
	if len(imgVulnResources) > 0 {
		logger.L().Info("Requesting images vulnerabilities results")
		cautils.StartSpinner()
		if err := k8sHandler.registryAdaptors.collectImagesVulnerabilities(k8sResourcesMap, allResources, ksResourceMap); err != nil {
			cautils.SetInfoMapForResources(fmt.Sprintf("failed to pull image scanning data: %s. for more information: https://hub.armosec.io/docs/configuration-of-image-vulnerabilities", err.Error()), imgVulnResources, sessionObj.InfoMap)
		} else {
			if isEmptyImgVulns(*ksResourceMap) {
				cautils.SetInfoMapForResources("image scanning is not configured. for more information: https://hub.armosec.io/docs/configuration-of-image-vulnerabilities", imgVulnResources, sessionObj.InfoMap)
			}
		}
		cautils.StopSpinner()
		logger.L().Success("Requested images vulnerabilities results")
	}

	hostResources := cautils.MapHostResources(ksResourceMap)
	// check that controls use host sensor resources
	if len(hostResources) > 0 {
		if sessionObj.Metadata.ScanMetadata.HostScanner {
			logger.L().Info("Requesting Host scanner data")
			cautils.StartSpinner()
			infoMap, err := k8sHandler.collectHostResources(ctx, allResources, ksResourceMap)
			if err != nil {
				logger.L().Ctx(ctx).Warning("failed to collect host scanner resources", helpers.Error(err))
				cautils.SetInfoMapForResources(err.Error(), hostResources, sessionObj.InfoMap)
			} else if k8sHandler.hostSensorHandler == nil {
				// using hostSensor mock
				cautils.SetInfoMapForResources("failed to init host scanner", hostResources, sessionObj.InfoMap)
			} else {
				if len(infoMap) > 0 {
					sessionObj.InfoMap = infoMap
				}
			}
			cautils.StopSpinner()
			logger.L().Success("Requested Host scanner data")
		} else {
			cautils.SetInfoMapForResources("enable-host-scan flag not used. For more information: https://hub.armosec.io/docs/host-sensor", hostResources, sessionObj.InfoMap)
		}
	}

	if err := k8sHandler.collectRbacResources(allResources); err != nil {
		logger.L().Ctx(ctx).Warning("failed to collect rbac resources", helpers.Error(err))
	}

	cloudResources := cautils.MapCloudResources(ksResourceMap)

	setMapNamespaceToNumOfResources(ctx, allResources, sessionObj)

	// check that controls use cloud resources
	if len(cloudResources) > 0 {
		err := k8sHandler.collectCloudResources(ctx, sessionObj, allResources, ksResourceMap, cloudResources)
		if err != nil {
			cautils.SetInfoMapForResources(err.Error(), cloudResources, sessionObj.InfoMap)
			logger.L().Debug("failed to collect cloud data", helpers.Error(err))
		}
	}

	return k8sResourcesMap, allResources, ksResourceMap, nil
}

func (k8sHandler *K8sResourceHandler) collectCloudResources(ctx context.Context, sessionObj *cautils.OPASessionObj, allResources map[string]workloadinterface.IMetadata, ksResourceMap *cautils.KSResources, cloudResources []string) error {
	clusterName := cautils.ClusterName
	provider := cloudsupport.GetCloudProvider(clusterName)
	if provider == "" {
		return fmt.Errorf("failed to get cloud provider, cluster: %s", clusterName)
	}

	if sessionObj.Metadata != nil && sessionObj.Metadata.ContextMetadata.ClusterContextMetadata != nil {
		sessionObj.Metadata.ContextMetadata.ClusterContextMetadata.CloudProvider = provider
	}
	logger.L().Debug("cloud", helpers.String("cluster", clusterName), helpers.String("clusterName", clusterName), helpers.String("provider", provider))

	for resourceKind, resourceGetter := range cloudResourceGetterMapping {
		if !cloudResourceRequired(cloudResources, resourceKind) {
			continue
		}

		logger.L().Debug("Collecting cloud data ", helpers.String("resourceKind", resourceKind))
		wl, err := resourceGetter(clusterName, provider)
		if err != nil {
			if !strings.Contains(err.Error(), cloudv1.NotSupportedMsg) {
				// Return error with useful info on how to configure credentials for getting cloud provider info
				logger.L().Debug("failed to get cloud data", helpers.String("resourceKind", resourceKind), helpers.Error(err))
				err = fmt.Errorf("failed to get %s descriptive information. Read more: https://hub.armosec.io/docs/kubescape-integration-with-cloud-providers", strings.ToUpper(provider))
				cautils.SetInfoMapForResources(err.Error(), cloudResources, sessionObj.InfoMap)
			}

			continue
		}

		allResources[wl.GetID()] = wl
		(*ksResourceMap)[fmt.Sprintf("%s/%s", wl.GetApiVersion(), wl.GetKind())] = []string{wl.GetID()}
	}

	// get api server info resource
	if cloudResourceRequired(cloudResources, string(cloudsupport.TypeApiServerInfo)) {
		if err := k8sHandler.collectAPIServerInfoResource(allResources, ksResourceMap); err != nil {
			logger.L().Ctx(ctx).Warning("failed to collect api server info resource", helpers.Error(err))

			return err
		}
	}

	return nil
}

func cloudResourceRequired(cloudResources []string, resource string) bool {
	for _, cresource := range cloudResources {
		if strings.Contains(cresource, resource) {
			return true
		}
	}
	return false
}

func (k8sHandler *K8sResourceHandler) collectAPIServerInfoResource(allResources map[string]workloadinterface.IMetadata, ksResourceMap *cautils.KSResources) error {
	clusterAPIServerInfo, err := k8sHandler.k8s.DiscoveryClient.ServerVersion()
	if err != nil {
		return err
	}
	resource := cloudsupport.NewApiServerVersionInfo(clusterAPIServerInfo)
	allResources[resource.GetID()] = resource
	(*ksResourceMap)[fmt.Sprintf("%s/%s", resource.GetApiVersion(), resource.GetKind())] = []string{resource.GetID()}

	return nil
}

func (k8sHandler *K8sResourceHandler) GetClusterAPIServerInfo(ctx context.Context) *version.Info {
	clusterAPIServerInfo, err := k8sHandler.k8s.DiscoveryClient.ServerVersion()
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to discover API server information", helpers.Error(err))
		return nil
	}
	return clusterAPIServerInfo
}

// set  namespaceToNumOfResources map in report
func setMapNamespaceToNumOfResources(ctx context.Context, allResources map[string]workloadinterface.IMetadata, sessionObj *cautils.OPASessionObj) {

	mapNamespaceToNumberOfResources := make(map[string]int)
	for _, resource := range allResources {
		if obj := workloadinterface.NewWorkloadObj(resource.GetObject()); obj != nil {
			ownerReferences, err := obj.GetOwnerReferences()
			if err == nil {
				// Add an object to the map if the object does not have a parent but is contained within a namespace (except Job)
				if len(ownerReferences) == 0 {
					if ns := resource.GetNamespace(); ns != "" {
						if obj.GetKind() != "Job" {
							mapNamespaceToNumberOfResources[ns]++
						}
					}
				}
			} else {
				logger.L().Ctx(ctx).Warning(fmt.Sprintf("failed to get owner references. Resource %s will not be counted", obj.GetName()), helpers.Error(err))
			}
		}
	}
	sessionObj.SetMapNamespaceToNumberOfResources(mapNamespaceToNumberOfResources)
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
		if namespace != "" {
			clientResource = k8sHandler.k8s.DynamicClient.Resource(*resource)
		} else if k8sinterface.IsNamespaceScope(resource) {
			clientResource = k8sHandler.k8s.DynamicClient.Resource(*resource).Namespace(namespace)
		} else if k8sHandler.fieldSelector.GetClusterScope(resource) {
			clientResource = k8sHandler.k8s.DynamicClient.Resource(*resource)
		} else {
			continue
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

func (k8sHandler *K8sResourceHandler) collectHostResources(ctx context.Context, allResources map[string]workloadinterface.IMetadata, ksResourceMap *cautils.KSResources) (map[string]apis.StatusInfo, error) {
	logger.L().Debug("Collecting host scanner resources")
	hostResources, infoMap, err := k8sHandler.hostSensorHandler.CollectResources(ctx)
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
