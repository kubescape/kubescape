package resourcehandler

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/hostsensorutils"
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

	// build resources map
	// map resources based on framework required resources: map["/group/version/kind"][]<k8s workloads ids>
	k8sResourcesMap := setResourceMap(frameworks)

	// get namespace and labels from designator (ignore cluster labels)
	_, namespace, labels := armotypes.DigestPortalDesignator(designator)

	// pull k8s recourses
	if err := k8sHandler.pullResources(k8sResourcesMap, allResources, namespace, labels); err != nil {
		return k8sResourcesMap, allResources, err
	}
	if err := getCloudProviderDescription(allResources, k8sResourcesMap); err != nil {
		cautils.WarningDisplay(os.Stdout, fmt.Sprintf("Warning: %v\n", err.Error()))
	}
	if err := k8sHandler.collectHostResources(allResources, k8sResourcesMap); err != nil {
		return k8sResourcesMap, allResources, err
	}

	if err := k8sHandler.collectRbacResources(allResources); err != nil {
		fmt.Println("failed to collect rbac resources")
	}

	cautils.SuccessTextDisplay("Accessed successfully to Kubernetes objects")
	return k8sResourcesMap, allResources, nil
}

func mock(allResources map[string]workloadinterface.IMetadata, k8sResourcesMap *cautils.K8SResources) error {

	mockdata := `{ "name": "ben-kubescape-demo-01", "node_config": { "machine_type": "e2-medium", "disk_size_gb": 100, "oauth_scopes": [ "https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/https://console.cloud.google.com/kubernetes/clusters/details/us-central1-c/ben-kubescape-demo-01/details?authuser=0&project=elated-pottery-310110auth/monitoring", "https://www.googleapis.com/auth/servicecontrol", "https://www.googleapis.com/auth/service.management.readonly", "https://www.googleapis.com/auth/trace.append" ], "service_account": "default", "metadata": { "disable-legacy-endpoints": "true" }, "image_type": "COS_CONTAINERD", "disk_type": "pd-standard", "shielded_instance_config": { "enable_integrity_monitoring": true } }, "master_auth": { "cluster_ca_certificate": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVMRENDQXBTZ0F3SUJBZ0lRQXAvRDRPOGQ2Y010SjRqQWZnZzUzVEFOQmdrcWhraUc5dzBCQVFzRkFEQXYKTVMwd0t3WURWUVFERXlReVpUUXlaakJpWkMxaU16TXlMVFE1TXpBdE9USTFNQzAzWWpJM1pETTRZelZrT1RNdwpJQmNOTWpFeE1URTNNRFl6TXpReFdoZ1BNakExTVRFeE1UQXdOek16TkRGYU1DOHhMVEFyQmdOVkJBTVRKREpsCk5ESm1NR0prTFdJek16SXRORGt6TUMwNU1qVXdMVGRpTWpka016aGpOV1E1TXpDQ0FhSXdEUVlKS29aSWh2Y04KQVFFQkJRQURnZ0dQQURDQ0FZb0NnZ0dCQUx0VEtPdkV5VUZpalFrallnTzlpVGdDMHlSQUhUZC9zdTJHWUxUMwp3czgvaEZ6dWRsSER3MjhPV0ZDV1BmUGpHZks5S00yVnluU2Q2aEFsWEFia3lVMXhVSGpDd1Z1dTVrMmlnSjNCCjVaZFhlcXFsc1JWWldQQ3BuOFVtVzF3RGZGbmp6WWJEQ1JxK2Z1R09iRGdrNkdmL1JxaFN2MTBvUnJqb2lPY0kKMkFRczFGbUdZdVM0dnVTZU95dmduc054UHgzdEtSdGtsUWZvZlphR2djS0xLNHRkOHkwRFR1SWMydDFJVlk1cApjb3dVTkZGRWJyckw3R1lKR2N2SGR3WG1NK1lZMWNGT2pGNlBzMUpHOFpCSGJ6ZU8xQmRFeGZWeFh2T1dTNEVsCkdsQ0hxUE1Pb3JjUld6eU1CcWQyYVNSVEFEaWVuUjhNU3AyeWtHMUY1YzNGOCtoZU40b1lXQmppdFg2M3QyR2UKQlg3TmFHY3hGSzdJbWloNnpQZ013UENHdlJCRUx3NmdQQlhDNEphSzVjNFVLTnJ3S1pXUzJRVCtNamJmdVdrNQpRMGtCRHhPQUllbUJEMzFkeHY3NTRDRVUwMmw1N1h5VTJ0TlB6aTd0OVdEU2RlSEtZNkcyR3h2aE5EMzZnWjEvCm4zQkU2Y3hYaXp0UzgyT3puK1lKdGRNWnZ3SURBUUFCbzBJd1FEQU9CZ05WSFE4QkFmOEVCQU1DQWdRd0R3WUQKVlIwVEFRSC9CQVV3QXdFQi96QWRCZ05WSFE0RUZnUVVkRUkxd2ROTFpQdzRpNkVGcExiVlZkTWlTTlF3RFFZSgpLb1pJaHZjTkFRRUxCUUFEZ2dHQkFJaFhpSkpIeVhZSXpzcGlDV3pYckFLNUlyNHd4VXFaNHV3SnlaQTQ2N3NTCng1RC9tT3ROcTlGVnVRZERDYnhjNWxqOWtzWEFHNjFoV08wV05aaW1LVmg0TnAwQ1pMTTJDUXpCamhDVVc1dWsKcGpwRkVsd0ovcFJ1cml1ZWoxS1E4VzA3TzY2S0pRMVVMKzRwMzNVSHJHOUFjd1hQMzNvR0RoMzliTE1mNXl3bQp2WUp1ZEw5cks4ZEw4cWZMcmhGTGpFY2lTRzNlRmI1cVMwQ3MvUERKcGRKTWFHQ2g1RVZBQjA0cUV1V0Vqam03CnloK0lMSjRBcjdVWHdyUm5Cc1F3K1duckY2c0M5STFsL1JnNHo5RTExck5lUVhUUE5Ld2ZkVzhqV21oaCs0dnMKV1pib2M0dDVnRzBXUkpoWFdQc2prL3JOQ2JyRkhOSndUMFhUWHBISitWV0lIVzdtaFV2enNFNFVwNExVMzhkTwpmNTBNbEh4YTlZaHBlZVVMUXdNcC9hdktCc1lpYkc4MzNlcGpjUmJFTi9mZkZreGN1MHpQYzg2eVlBb3hleWhLCjFOQnk2UmhTcEdkUXZTMUtibmFFZnJzb3hVcTRNNWxFMDhJblNwSGxIcCtVNExzek9wcWNLSkw5Y0lrWllONGUKeFpWZXRqeDdMY2hUR1c0ZUJwRHJqdz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K" }, "logging_service": "logging.googleapis.com/kubernetes", "monitoring_service": "monitoring.googleapis.com/kubernetes", "network": "default", "cluster_ipv4_cidr": "10.32.0.0/14", "addons_config": { "http_load_balancing": {}, "horizontal_pod_autoscaling": {}, "kubernetes_dashboard": { "disabled": true }, "network_policy_config": { "disabled": true }, "dns_cache_config": {} }, "subnetwork": "default", "node_pools": [ { "name": "default-pool", "config": { "machine_type": "e2-medium", "disk_size_gb": 100, "oauth_scopes": [ "https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/monitoring", "https://www.googleapis.com/auth/servicecontrol", "https://www.googleapis.com/auth/service.management.readonly", "https://www.googleapis.com/auth/trace.append" ], "service_account": "default", "metadata": { "disable-legacy-endpoints": "true" }, "image_type": "COS_CONTAINERD", "disk_type": "pd-standard", "shielded_instance_config": { "enable_integrity_monitoring": true } }, "initial_node_count": 3, "locations": [ "us-central1-c" ], "self_link": "https://container.googleapis.com/v1/projects/elated-pottery-310110/zones/us-central1-c/clusters/ben-kubescape-demo-01/nodePools/default-pool", "version": "1.21.5-gke.1302", "instance_group_urls": [ "https://www.googleapis.com/compute/v1/projects/elated-pottery-310110/zones/us-central1-c/instanceGroupManagers/gke-ben-kubescape-demo-0-default-pool-4483e885-grp" ], "status": 2, "autoscaling": {}, "management": { "auto_upgrade": true, "auto_repair": true }, "max_pods_constraint": { "max_pods_per_node": 110 }, "pod_ipv4_cidr_size": 24, "upgrade_settings": { "max_surge": 1 } } ], "locations": [ "us-central1-c" ], "label_fingerprint": "a9dc16a7", "legacy_abac": {}, "ip_allocation_policy": { "use_ip_aliases": true, "cluster_ipv4_cidr": "10.32.0.0/14", "services_ipv4_cidr": "10.22.128.0/20", "cluster_secondary_range_name": "gke-ben-kubescape-demo-01-pods-686ce31a", "services_secondary_range_name": "gke-ben-kubescape-demo-01-services-686ce31a", "cluster_ipv4_cidr_block": "10.32.0.0/14", "services_ipv4_cidr_block": "10.22.128.0/20" }, "master_authorized_networks_config": {}, "maintenance_policy": { "resource_version": "e3b0c442" }, "autoscaling": {}, "network_config": { "network": "projects/elated-pottery-310110/global/networks/default", "subnetwork": "projects/elated-pottery-310110/regions/us-central1/subnetworks/default", "default_snat_status": {} }, "default_max_pods_constraint": { "max_pods_per_node": 110 }, "authenticator_groups_config": {}, "database_encryption": { "state": 2 }, "shielded_nodes": { "enabled": true }, "release_channel": { "channel": 2 }, "self_link": "https://container.googleapis.com/v1/projects/elated-pottery-310110/zones/us-central1-c/clusters/ben-kubescape-demo-01", "zone": "us-central1-c", "endpoint": "34.71.124.239", "initial_cluster_version": "1.21.5-gke.1302", "current_master_version": "1.21.5-gke.1302", "current_node_version": "1.21.5-gke.1302", "create_time": "2021-11-17T07:33:38+00:00", "status": 2, "services_ipv4_cidr": "10.22.128.0/20", "instance_group_urls": [ "https://www.googleapis.com/compute/v1/projects/elated-pottery-310110/zones/us-central1-c/instanceGroupManagers/gke-ben-kubescape-demo-0-default-pool-4483e885-grp" ], "current_node_count": 3, "location": "us-central1-c" }`
	var mockmap (map[string]interface{})
	json.Unmarshal([]byte(mockdata), &mockmap)
	wl := cloudsupport.NewDescriptiveInfoFromCloudProvider(mockmap)
	wl.SetGroup("cloudvendordata.armo.cloud")
	wl.SetNamespace("v1beta0")
	wl.SetKind("description")
	wl.SetProvider("gke")

	allResources[wl.GetID()] = wl
	(*k8sResourcesMap)[fmt.Sprintf("%s/%s/%ss", wl.GetApiVersion(), wl.GetNamespace(), wl.GetKind())] = []string{wl.GetID()}

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
			}
			return err
		}

		allResources[wl.GetID()] = wl
		// k8sResourcesMap[<ID>] = workload
		(*k8sResourcesMap)[fmt.Sprintf("%s/%s/%ss", wl.GetApiVersion(), wl.GetNamespace(), wl.GetKind())] = []string{wl.GetID()}
	}
	return nil

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
		if w := workloadinterface.NewObject(resourceMap[i]); w != nil {
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
		groupResources := k8sinterface.ResourceGroupToString(hostResources[rscIdx].Group, hostResources[rscIdx].GetApiVersion(), hostResources[rscIdx].GetKind())
		for _, groupResource := range groupResources {
			allResources[hostResources[rscIdx].GetID()] = &hostResources[rscIdx]

			grpResourceList, ok := (*resourcesMap)[groupResource]
			if !ok {
				grpResourceList = make([]string, 0)
			}
			(*resourcesMap)[groupResource] = append(grpResourceList, hostResources[rscIdx].GetID())
		}
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
