package resourcehandler

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/opa-utils/reporthandling"
	"k8s.io/apimachinery/pkg/version"
)

type IResourceHandler interface {
	GetResources([]reporthandling.Framework, *armotypes.PortalDesignator) (*cautils.K8SResources, map[string]workloadinterface.IMetadata, error)
	GetClusterAPIServerInfo() *version.Info
}
