package cautils

import (
	"strings"

	"github.com/kubescape/k8s-interface/cloudsupport"
	cloudapis "github.com/kubescape/k8s-interface/cloudsupport/apis"
	"github.com/kubescape/opa-utils/reporthandling/apis"
)

var (
	ImageVulnResources  = []string{"ImageVulnerabilities"}
	HostSensorResources = []string{"KubeletConfiguration",
		"KubeletCommandLine",
		"OsReleaseFile",
		"KernelVersion",
		"LinuxSecurityHardeningStatus",
		"OpenPortsList",
		"LinuxKernelVariables",
		"KubeletInfo",
		"KubeProxyInfo",
		"ControlPlaneInfo",
		"CloudProviderInfo",
		"CNIInfo",
	}
	CloudResources = []string{
		cloudapis.CloudProviderDescribeKind,
		cloudapis.CloudProviderDescribeRepositoriesKind,
		cloudapis.CloudProviderListEntitiesForPoliciesKind,
		cloudapis.CloudProviderPolicyVersionKind,
		string(cloudsupport.TypeApiServerInfo),
	}
)

func MapExternalResource(externalResourceMap ExternalResources, resources []string) []string {
	var hostResources []string
	for k := range externalResourceMap {
		for _, resource := range resources {
			if strings.Contains(k, resource) {
				hostResources = append(hostResources, k)
			}
		}
	}
	return hostResources
}

func MapHostResources(externalResourceMap ExternalResources) []string {
	return MapExternalResource(externalResourceMap, HostSensorResources)
}

func MapImageVulnResources(externalResourceMap ExternalResources) []string {
	return MapExternalResource(externalResourceMap, ImageVulnResources)
}

func MapCloudResources(externalResourceMap ExternalResources) []string {
	return MapExternalResource(externalResourceMap, CloudResources)
}

func SetInfoMapForResources(info string, resources []string, errorMap map[string]apis.StatusInfo) {
	for _, resource := range resources {
		errorMap[resource] = apis.StatusInfo{
			InnerInfo:   info,
			InnerStatus: apis.StatusSkipped,
		}
	}
}
