package resourcehandler

import (
	"strings"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"k8s.io/utils/strings/slices"

	"github.com/kubescape/k8s-interface/k8sinterface"
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
	imgVulnResources := cautils.MapImageVulnResources(&ksResourcesMap)
	for _, resource := range imgVulnResources {
		if val, ok := ksResourcesMap[resource]; ok {
			if len(val) > 0 {
				return false
			}
		}
	}
	return true
}

func setK8sResourceMap(frameworks []reporthandling.Framework) *cautils.K8SResources {
	k8sResources := make(cautils.K8SResources)
	complexMap := setComplexK8sResourceMap(frameworks)
	for group := range complexMap {
		for version := range complexMap[group] {
			for resource := range complexMap[group][version] {
				groupResources := k8sinterface.ResourceGroupToString(group, version, resource)
				for _, groupResource := range groupResources {
					k8sResources[groupResource] = nil
				}
			}
		}
	}
	return &k8sResources
}

func setKSResourceMap(frameworks []reporthandling.Framework, resourceToControl map[string][]string) *cautils.KSResources {
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
	return &ksResources
}

func setComplexK8sResourceMap(frameworks []reporthandling.Framework) map[string]map[string]map[string]interface{} {
	k8sResources := make(map[string]map[string]map[string]interface{})
	for _, framework := range frameworks {
		for _, control := range framework.Controls {
			for _, rule := range control.Rules {
				for _, match := range rule.Match {
					insertResources(k8sResources, match)
				}
			}
		}
	}
	return k8sResources
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

func insertResources(k8sResources map[string]map[string]map[string]interface{}, match reporthandling.RuleMatchObjects) {
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
