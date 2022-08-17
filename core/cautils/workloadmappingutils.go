package cautils

import (
	"strings"

	"github.com/armosec/opa-utils/reporthandling/apis"
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

func MapArmoResource(armoResourceMap *KSResources, resources []string) []string {
	var hostResources []string
	for k := range *armoResourceMap {
		for _, resource := range resources {
			if strings.Contains(k, resource) {
				hostResources = append(hostResources, k)
			}
		}
	}
	return hostResources
}

func MapHostResources(armoResourceMap *KSResources) []string {
	return MapArmoResource(armoResourceMap, HostSensorResources)
}

func MapImageVulnResources(armoResourceMap *KSResources) []string {
	return MapArmoResource(armoResourceMap, ImageVulnResources)
}

func MapCloudResources(armoResourceMap *KSResources) []string {
	return MapArmoResource(armoResourceMap, CloudResources)
}

func SetInfoMapForResources(info string, resources []string, errorMap map[string]apis.StatusInfo) {
	for _, resource := range resources {
		errorMap[resource] = apis.StatusInfo{
			InnerInfo:   info,
			InnerStatus: apis.StatusSkipped,
		}
	}
}
