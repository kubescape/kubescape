package hostsensorutils

import (
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/opa-utils/reporthandling/apis"
)

var (
	KubeletConfiguration         = "KubeletConfiguration"
	OsReleaseFile                = "OsReleaseFile"
	KernelVersion                = "KernelVersion"
	LinuxSecurityHardeningStatus = "LinuxSecurityHardeningStatus"
	OpenPortsList                = "OpenPortsList"
	LinuxKernelVariables         = "LinuxKernelVariables"
	KubeletCommandLine           = "KubeletCommandLine"
	KubeletInfo                  = "KubeletInfo"
	KubeProxyInfo                = "KubeProxyInfo"
	ControlPlaneInfo             = "ControlPlaneInfo"
	CloudProviderInfo            = "CloudProviderInfo"
	CNIInfo                      = "CNIInfo"

	MapHostSensorResourceToApiGroup = map[string]string{
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
)

func addInfoToMap(resource string, infoMap map[string]apis.StatusInfo, err error) {
	group, version := k8sinterface.SplitApiVersion(MapHostSensorResourceToApiGroup[resource])
	r := k8sinterface.JoinResourceTriplets(group, version, resource)
	infoMap[r] = apis.StatusInfo{
		InnerStatus: apis.StatusSkipped,
		InnerInfo:   err.Error(),
	}
}
