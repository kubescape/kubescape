package resourcehandler

import (
	"context"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"k8s.io/apimachinery/pkg/version"
)

type IResourceHandler interface {
	GetResources(context.Context, *cautils.OPASessionObj, *armotypes.PortalDesignator) (*cautils.K8SResources, map[string]workloadinterface.IMetadata, *cautils.KSResources, error)
	GetClusterAPIServerInfo(ctx context.Context) *version.Info
}
