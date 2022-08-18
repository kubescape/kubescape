package cautils

import (
	"strings"

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
	}
	CloudResources = []string{"ClusterDescribe"}
)

func MapKSResource(ksResourceMap *KSResources, resources []string) []string {
	var hostResources []string
	for k := range *ksResourceMap {
		for _, resource := range resources {
			if strings.Contains(k, resource) {
				hostResources = append(hostResources, k)
			}
		}
	}
	return hostResources
}

func MapHostResources(ksResourceMap *KSResources) []string {
	return MapKSResource(ksResourceMap, HostSensorResources)
}

func MapImageVulnResources(ksResourceMap *KSResources) []string {
	return MapKSResource(ksResourceMap, ImageVulnResources)
}

func MapCloudResources(ksResourceMap *KSResources) []string {
	return MapKSResource(ksResourceMap, CloudResources)
}

func SetInfoMapForResources(info string, resources []string, errorMap map[string]apis.StatusInfo) {
	for _, resource := range resources {
		errorMap[resource] = apis.StatusInfo{
			InnerInfo:   info,
			InnerStatus: apis.StatusSkipped,
		}
	}
}
