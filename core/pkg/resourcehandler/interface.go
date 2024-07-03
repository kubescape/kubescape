package resourcehandler

import (
	"context"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"k8s.io/apimachinery/pkg/version"
)

type IResourceHandler interface {
	GetResources(context.Context, *cautils.OPASessionObj, *cautils.ScanInfo) (cautils.K8SResources, map[string]workloadinterface.IMetadata, cautils.ExternalResources, map[string]bool, error)
	GetClusterAPIServerInfo(ctx context.Context) *version.Info
	GetCloudProvider() string
}
