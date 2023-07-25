package resourcehandler

import (
	"fmt"
	"strings"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"k8s.io/utils/strings/slices"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
)

var (
	ClusterDescribe              = "ClusterDescribe"
	DescribeRepositories         = "DescribeRepositories"
	ListEntitiesForPolicies      = "ListEntitiesForPolicies"
	KubeletConfiguration         = "KubeletConfiguration"
	OsReleaseFile                = "OsReleaseFile"
	KernelVersion                = "KernelVersion"
	LinuxSecurityHardeningStatus = "LinuxSecurityHardeningStatus"
	OpenPortsList                = "OpenPortsList"
	LinuxKernelVariables         = "LinuxKernelVariables"
	KubeletCommandLine           = "KubeletCommandLine"
	ImageVulnerabilities         = "ImageVulnerabilities"
	KubeletInfo                  = "KubeletInfo"
	KubeProxyInfo                = "KubeProxyInfo"
	ControlPlaneInfo             = "ControlPlaneInfo"
	CloudProviderInfo            = "CloudProviderInfo"
	CNIInfo                      = "CNIInfo"

	MapResourceToApiGroup = map[string]string{
		KubeletConfiguration:         "hostdata.kubescape.cloud/v1beta0",
		OsReleaseFile:                "hostdata.kubescape.cloud/v1beta0",
		KubeletCommandLine:           "hostdata.kubescape.cloud/v1beta0",
		KernelVersion:                "hostdata.kubescape.cloud/v1beta0",
		LinuxSecurityHardeningStatus: "hostdata.kubescape.cloud/v1beta0",
		OpenPortsList:                "hostdata.kubescape.cloud/v1beta0",
		LinuxKernelVariables:         "hostdata.kubescape.cloud/v1beta0",
		KubeletInfo:                  "hostdata.kubescape.cloud/v1beta0",
		KubeProxyInfo:                "hostdata.kubescape.cloud/v1beta0",
		ControlPlaneInfo:             "hostdata.kubescape.cloud/v1beta0",
		CloudProviderInfo:            "hostdata.kubescape.cloud/v1beta0",
		CNIInfo:                      "hostdata.kubescape.cloud/v1beta0",
	}
	MapResourceToApiGroupVuln = map[string][]string{
		ImageVulnerabilities: {"armo.vuln.images/v1", "image.vulnscan.com/v1"}}
	MapResourceToApiGroupCloud = map[string][]string{
		ClusterDescribe:         {"container.googleapis.com/v1", "eks.amazonaws.com/v1", "management.azure.com/v1"},
		DescribeRepositories:    {"eks.amazonaws.com/v1"}, //TODO - add google and azure when they are supported
		ListEntitiesForPolicies: {"eks.amazonaws.com/v1"}, //TODO - add google and azure when they are supported
	}
)

func isEmptyImgVulns(ksResourcesMap cautils.KSResources) bool {
	imgVulnResources := cautils.MapImageVulnResources(ksResourcesMap)
	for _, resource := range imgVulnResources {
		if val, ok := ksResourcesMap[resource]; ok {
			if len(val) > 0 {
				return false
			}
		}
	}
	return true
}

func getQueryableResourceMapFromPolicies(frameworks []reporthandling.Framework, workload workloadinterface.IMetadata) (QueryableResources, map[string]bool) {
	queryableResources := make(QueryableResources)
	excludedRulesMap := make(map[string]bool)

	var ownerReferenceKind string
	var namespace string
	if workload != nil {
		ownerReferenceKind = getOwnerReferenceKind(workload)
		if k8sinterface.IsResourceInNamespaceScope(workload.GetKind()) {
			namespace = workload.GetNamespace()
		} else if workload.GetKind() == "Namespace" {
			namespace = workload.GetName()
		}
	}

	for _, framework := range frameworks {
		for _, control := range framework.Controls {
			for _, rule := range control.Rules {
				var resourcesFilterMap map[string]bool = nil
				// for workload scan, we need to filter the resources according to the given workload and its owner reference
				if workload != nil {
					if resourcesFilterMap = filterRuleMatchesForWorkload(workload.GetKind(), ownerReferenceKind, rule.Match); resourcesFilterMap == nil {
						// rule does not apply to this workload
						excludedRulesMap[rule.Name] = false
						continue
					}
				}
				for _, match := range rule.Match {
					updateQueryableResourcesMapFromRuleMatchObject(&match, resourcesFilterMap, queryableResources, namespace)
				}
			}
		}
	}

	return queryableResources, excludedRulesMap
}

// filterRuleMatches returns a map, of which resources should be queried for a given workload and its owner reference
// The map is of the form: map[<resource>]bool (The bool value indicates whether the resource should be queried or not)
// The function will return a nil map if the rule does not apply to the given workload
func filterRuleMatchesForWorkload(workloadKind, ownerReferenceKind string, matchObjects []reporthandling.RuleMatchObjects) map[string]bool {
	resourceMap := make(map[string]bool)
	for _, match := range matchObjects {
		for _, resource := range match.Resources {
			resourceMap[resource] = false
		}
	}

	// rule does not apply to this workload
	if _, exists := resourceMap[workloadKind]; !exists {
		return nil
	}

	workloadKinds := map[string]bool{
		"Pod":         false,
		"DaemonSet":   false,
		"Deployment":  false,
		"ReplicaSet":  false,
		"StatefulSet": false,
		"CronJob":     false,
		"Job":         false,
	}

	_, isInputResourceWorkload := workloadKinds[workloadKind]

	//  has owner reference
	if isInputResourceWorkload && ownerReferenceKind != "" {
		// owner reference kind exists in the matches - that means the rule does not apply to the given workload
		if _, exist := resourceMap[ownerReferenceKind]; exist {
			return nil
		}
	}

	for r := range resourceMap {
		// we don't need to query the same resource
		if r == workloadKind {
			continue
		}

		_, isCurrentResourceWorkload := workloadKinds[r]
		resourceMap[r] = !isCurrentResourceWorkload || !isInputResourceWorkload
	}

	return resourceMap
}

// getOwnerReferenceKind returns the kind of the first owner reference of the given object
// If the object has no owner references or not a valid workload, returns an empty string
func getOwnerReferenceKind(object workloadinterface.IMetadata) string {
	if !k8sinterface.IsTypeWorkload(object.GetObject()) {
		return ""
	}
	wl := workloadinterface.NewWorkloadObj(object.GetObject())
	ownerReferences, err := wl.GetOwnerReferences()
	if err != nil || len(ownerReferences) == 0 {
		return ""
	}
	return ownerReferences[0].Kind
}

// updateQueryableResourcesMapFromMatch updates the queryableResources map with the relevant resources from the match object.
// if namespace is not empty, the namespace filter is added to the queryable resources (which are namespaced)
// if resourcesFilterMap is not nil, only the resources with value 'true' will be added to the queryable resources
func updateQueryableResourcesMapFromRuleMatchObject(match *reporthandling.RuleMatchObjects, resourcesFilterMap map[string]bool, queryableResources QueryableResources, namespace string) {
	for _, apiGroup := range match.APIGroups {
		for _, apiVersions := range match.APIVersions {
			for _, resource := range match.Resources {
				if resourcesFilterMap != nil {
					if relevant := resourcesFilterMap[resource]; !relevant {
						continue
					}
				}

				groupResources := k8sinterface.ResourceGroupToString(apiGroup, apiVersions, resource)
				globalFieldSelector := ""
				// if namespace filter is set, we are scanning a workload in a specific namespace
				if namespace != "" {
					// if the resource is namespace, we add the name filter
					if resource == "Namespace" {
						globalFieldSelector = fmt.Sprintf("metadata.name=%s", namespace)
						// if the resource is namespaced we add the namespace filter
					} else if k8sinterface.IsResourceInNamespaceScope(resource) {
						globalFieldSelector = fmt.Sprintf("metadata.namespace=%s", namespace)
					}
				}

				for _, groupResource := range groupResources {
					queryableResource := QueryableResource{
						GroupVersionResourceTriplet: groupResource,
					}
					queryableResource.AddFieldSelector(globalFieldSelector)

					if match.FieldSelector == nil || len(match.FieldSelector) == 0 {
						queryableResources.Add(queryableResource)
						continue
					}

					for _, fieldSelector := range match.FieldSelector {
						qrCopy := queryableResource.Copy()
						qrCopy.AddFieldSelector(fieldSelector)
						queryableResources.Add(qrCopy)
					}

				}
			}
		}
	}
}

func setKSResourceMap(frameworks []reporthandling.Framework, resourceToControl map[string][]string) cautils.KSResources {
	ksResources := make(cautils.KSResources)
	complexMap := setComplexKSResourceMap(frameworks, resourceToControl)
	for group := range complexMap {
		for version := range complexMap[group] {
			for resource := range complexMap[group][version] {
				groupResources := k8sinterface.ResourceGroupToString(group, version, resource)
				for _, groupResource := range groupResources {
					ksResources[groupResource] = nil
				}
			}
		}
	}
	return ksResources
}

// [group][versionn][resource]
func setComplexKSResourceMap(frameworks []reporthandling.Framework, resourceToControls map[string][]string) map[string]map[string]map[string]interface{} {
	k8sResources := make(map[string]map[string]map[string]interface{})
	for _, framework := range frameworks {
		for _, control := range framework.Controls {
			for _, rule := range control.Rules {
				for _, match := range rule.DynamicMatch {
					insertKSResourcesAndControls(k8sResources, match, resourceToControls, control)
				}
			}
		}
	}
	return k8sResources
}

func mapKSResourceToApiGroup(resource string) []string {
	if val, ok := MapResourceToApiGroup[resource]; ok {
		return []string{val}
	}
	if val, ok := MapResourceToApiGroupCloud[resource]; ok {
		return val
	}
	if val, ok := MapResourceToApiGroupVuln[resource]; ok {
		return val
	}
	return []string{}
}

func insertControls(resource string, resourceToControl map[string][]string, control reporthandling.Control) {
	ksResources := mapKSResourceToApiGroup(resource)
	for _, ksResource := range ksResources {
		group, version := k8sinterface.SplitApiVersion(ksResource)
		r := k8sinterface.JoinResourceTriplets(group, version, resource)
		if _, ok := resourceToControl[r]; !ok {
			resourceToControl[r] = append(resourceToControl[r], control.ControlID)
		} else {
			if !slices.Contains(resourceToControl[r], control.ControlID) {
				resourceToControl[r] = append(resourceToControl[r], control.ControlID)
			}
		}
	}
}

func insertKSResourcesAndControls(k8sResources map[string]map[string]map[string]interface{}, match reporthandling.RuleMatchObjects, resourceToControl map[string][]string, control reporthandling.Control) {
	for _, apiGroup := range match.APIGroups {
		if v, ok := k8sResources[apiGroup]; !ok || v == nil {
			k8sResources[apiGroup] = make(map[string]map[string]interface{})
		}
		for _, apiVersions := range match.APIVersions {
			if v, ok := k8sResources[apiGroup][apiVersions]; !ok || v == nil {
				k8sResources[apiGroup][apiVersions] = make(map[string]interface{})
			}
			for _, resource := range match.Resources {
				if _, ok := k8sResources[apiGroup][apiVersions][resource]; !ok {
					k8sResources[apiGroup][apiVersions][resource] = nil
				}
				insertControls(resource, resourceToControl, control)
			}
		}
	}
}

func getGroupNVersion(apiVersion string) (string, string) {
	gv := strings.Split(apiVersion, "/")
	group, version := "", ""
	if len(gv) >= 1 {
		group = gv[0]
	}
	if len(gv) >= 2 {
		version = gv[1]
	}
	return group, version
}
