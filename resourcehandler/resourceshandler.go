package resourcehandler

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/opa-utils/reporthandling"
	"k8s.io/apimachinery/pkg/version"
)

type IResourceHandler interface {
	GetResources(frameworks []reporthandling.Framework, designator *armotypes.PortalDesignator) (*cautils.K8SResources, error)
	GetClusterAPIServerInfo() *version.Info
}
