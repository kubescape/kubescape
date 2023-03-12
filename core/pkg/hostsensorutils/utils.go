package hostsensorutils

import (
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/opa-utils/reporthandling/apis"
)

// scannerResource is the enumerated type listing all resources from the host-scanner.
type scannerResource string

const (
	// host-scanner resources

	KubeletConfiguration         scannerResource = "KubeletConfiguration"
	OsReleaseFile                scannerResource = "OsReleaseFile"
	KernelVersion                scannerResource = "KernelVersion"
	LinuxSecurityHardeningStatus scannerResource = "LinuxSecurityHardeningStatus"
	OpenPortsList                scannerResource = "OpenPortsList"
	LinuxKernelVariables         scannerResource = "LinuxKernelVariables"
	KubeletCommandLine           scannerResource = "KubeletCommandLine"
	KubeletInfo                  scannerResource = "KubeletInfo"
	KubeProxyInfo                scannerResource = "KubeProxyInfo"
	ControlPlaneInfo             scannerResource = "ControlPlaneInfo"
	CloudProviderInfo            scannerResource = "CloudProviderInfo"
	CNIInfo                      scannerResource = "CNIInfo"
)

func mapHostSensorResourceToApiGroup(r scannerResource) string {
	switch r {
	case
		KubeletConfiguration,
		OsReleaseFile,
		KubeletCommandLine,
		KernelVersion,
		LinuxSecurityHardeningStatus,
		OpenPortsList,
		LinuxKernelVariables,
		KubeletInfo,
		KubeProxyInfo,
		ControlPlaneInfo,
		CloudProviderInfo,
		CNIInfo:
		return "hostdata.kubescape.cloud/v1beta0"
	default:
		return ""
	}
}

func (r scannerResource) String() string {
	return string(r)
}

func addInfoToMap(resource scannerResource, infoMap map[string]apis.StatusInfo, err error) {
	group, version := k8sinterface.SplitApiVersion(mapHostSensorResourceToApiGroup(resource))
	r := k8sinterface.JoinResourceTriplets(group, version, resource.String())
	infoMap[r] = apis.StatusInfo{
		InnerStatus: apis.StatusSkipped,
		InnerInfo:   err.Error(),
	}
}
