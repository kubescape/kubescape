package cautils

import (
	"slices"
	"strings"

	"github.com/kubescape/k8s-interface/cloudsupport"
	cloudapis "github.com/kubescape/k8s-interface/cloudsupport/apis"
	"github.com/kubescape/opa-utils/reporthandling/apis"
)

// ComponentVulnAPIVersion is the group/version of the componentvulns package.
const ComponentVulnAPIVersion = "componentvulns.kubescape.cloud/v1beta0"

var (
	ImageVulnResources = []string{"ImageVulnerabilities"}
	// ComponentVulnResources are the kinds built by the componentvulns
	// package, served under ComponentVulnAPIVersion.
	ComponentVulnResources = []string{
		"APIServerVulnerabilities",
		"KubeletVulnerabilities",
		"ContainerRuntimeVulnerabilities",
	}
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

// MapComponentVulnResources matches the complete group/version/kind: a kind
// or substring match would also pick up a foreign group serving the same kind,
// or kinds such as OtherKubeletVulnerabilities.
func MapComponentVulnResources(externalResourceMap ExternalResources) []string {
	var resources []string
	for k := range externalResourceMap {
		kind, ok := strings.CutPrefix(k, ComponentVulnAPIVersion+"/")
		if ok && slices.Contains(ComponentVulnResources, kind) {
			resources = append(resources, k)
		}
	}
	slices.Sort(resources)
	return resources
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
