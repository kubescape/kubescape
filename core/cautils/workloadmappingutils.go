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
		"LinuxKernelVariables"}
	CloudResources = []string{"ClusterDescribe"}
)

func MapHostResources(armoResourceMap *ArmoResources) []string {
	var hostResources []string
	for k := range *armoResourceMap {
		for _, resource := range HostSensorResources {
			if strings.Contains(k, resource) {
				hostResources = append(hostResources, k)
			}
		}
	}
	return hostResources
}

func MapImageVulnResources(armoResourceMap *ArmoResources) []string {
	var imgVulnResources []string
	for k := range *armoResourceMap {
		for _, resource := range HostSensorResources {
			if strings.Contains(k, resource) {
				imgVulnResources = append(ImageVulnResources, k)
			}
		}
	}
	return imgVulnResources
}

func MapCloudResources(armoResourceMap *ArmoResources) []string {
	var cloudResources []string
	for k := range *armoResourceMap {
		for _, resource := range CloudResources {
			if strings.Contains(k, resource) {
				cloudResources = append(cloudResources, k)
			}
		}
	}
	return cloudResources
}

func SetInfoMapForResources(info string, resources []string, errorMap map[string]apis.StatusInfo) {
	for _, resource := range resources {
		errorMap[resource] = apis.StatusInfo{
			InnerInfo:   info,
			InnerStatus: apis.StatusSkipped,
		}
	}
}

// func PullResources(allResources map[string]workloadinterface.IMetadata) {

// 	mapHostResources(allResources)
// 	mapCloudResources(allResources)
// 	return allResources

// }
