package resourcehandler

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/kubescape/v2/core/cautils"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"k8s.io/apimachinery/pkg/version"
)

type IResourceHandler interface {
	GetResources(*cautils.OPASessionObj, *armotypes.PortalDesignator) (*cautils.K8SResources, map[string]workloadinterface.IMetadata, *cautils.KSResources, error)
	GetClusterAPIServerInfo() *version.Info
}
