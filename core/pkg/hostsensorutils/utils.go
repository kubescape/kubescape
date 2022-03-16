package hostsensorutils

import (
	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/opa-utils/reporthandling/apis"
)

var (
	KubeletConfiguration         = "KubeletConfiguration"
	OsReleaseFile                = "OsReleaseFile"
	KernelVersion                = "KernelVersion"
	LinuxSecurityHardeningStatus = "LinuxSecurityHardeningStatus"
	OpenPortsList                = "OpenPortsList"
	LinuxKernelVariables         = "LinuxKernelVariables"
	KubeletCommandLine           = "KubeletCommandLine"

	MapResourceToApiGroup = map[string]string{
		KubeletConfiguration:         "hostdata.kubescape.cloud/v1beta0",
		OsReleaseFile:                "hostdata.kubescape.cloud/v1beta0/OsReleaseFile",
		KubeletCommandLine:           "hostdata.kubescape.cloud/v1beta0/KubeletCommandLine",
		KernelVersion:                "hostdata.kubescape.cloud/v1beta0/KernelVersion",
		LinuxSecurityHardeningStatus: "hostdata.kubescape.cloud/v1beta0/LinuxSecurityHardeningStatus",
		OpenPortsList:                "hostdata.kubescape.cloud/v1beta0/OpenPortsList",
		LinuxKernelVariables:         "hostdata.kubescape.cloud/v1beta0/LinuxKernelVariables",
	}
)

func addInfoToMap(resource string, errorMap map[string]apis.StatusInfo, err error) {
	group, version := k8sinterface.SplitApiVersion(MapResourceToApiGroup[resource])
	r := k8sinterface.JoinResourceTriplets(group, version, KubeletConfiguration)
	errorMap[r] = apis.StatusInfo{
		InnerStatus: apis.StatusSkipped,
		InnerInfo:   err.Error(),
	}
}
