package hostsensorutils

import (
	"math/rand"

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

	MapHostSensorResourceToApiGroup = map[string]string{
		KubeletConfiguration:         "hostdata.kubescape.cloud/v1beta0",
		OsReleaseFile:                "hostdata.kubescape.cloud/v1beta0",
		KubeletCommandLine:           "hostdata.kubescape.cloud/v1beta0",
		KernelVersion:                "hostdata.kubescape.cloud/v1beta0",
		LinuxSecurityHardeningStatus: "hostdata.kubescape.cloud/v1beta0",
		OpenPortsList:                "hostdata.kubescape.cloud/v1beta0",
		LinuxKernelVariables:         "hostdata.kubescape.cloud/v1beta0",
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

func randomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyz0123456789")

	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}
