package resourcehandler

import (
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
)

// utils which are common to all resource handlers
func addWorkloadToResourceMaps(k8sResources cautils.K8SResources, allResources map[string]workloadinterface.IMetadata, wl workloadinterface.IWorkload) {
	if wl == nil {
		return
	}

	allResources[wl.GetID()] = wl

	resourceGroup := k8sinterface.ResourceGroupToSlice(wl.GetGroup(), wl.GetVersion(), wl.GetKind())[0]
	k8sResources[resourceGroup] = append(k8sResources[resourceGroup], wl.GetID())
}
