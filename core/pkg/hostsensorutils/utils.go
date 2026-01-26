package hostsensorutils

import (
	"github.com/kubescape/k8s-interface/hostsensor"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/opa-utils/reporthandling/apis"
)

func addInfoToMap(resource hostsensor.HostSensorResource, infoMap map[string]apis.StatusInfo, err error) {
	group, version := k8sinterface.SplitApiVersion(hostsensor.MapHostSensorResourceToApiGroup(resource))
	r := k8sinterface.JoinResourceTriplets(group, version, resource.String())
	infoMap[r] = apis.StatusInfo{
		InnerStatus: apis.StatusSkipped,
		InnerInfo:   err.Error(),
	}
}
