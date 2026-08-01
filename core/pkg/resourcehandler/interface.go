package resourcehandler

import (
	"context"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"k8s.io/apimachinery/pkg/version"
)

type IResourceHandler interface {
	GetResources(context.Context, *cautils.OPASessionObj, *cautils.ScanInfo) (cautils.K8SResources, map[string]workloadinterface.IMetadata, cautils.ExternalResources, map[string]bool, error)
	// StreamResourcesBatches streams resources in batches to reduce memory usage on large clusters.
	// Returns a channel of ResourceBatch objects, the expected number of namespace batches, and an error if streaming setup fails.
	// The caller must process batches sequentially and ensure proper cleanup.
	StreamResourcesBatches(ctx context.Context, sessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) (<-chan *cautils.ResourceBatch, <-chan error, int, error)
	GetClusterAPIServerInfo(ctx context.Context) *version.Info
	GetCloudProvider() string
}
