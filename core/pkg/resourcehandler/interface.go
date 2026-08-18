package resourcehandler

import (
	"context"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"k8s.io/apimachinery/pkg/version"
)

type IResourceHandler interface {
	GetResources(context.Context, *cautils.OPASessionObj, *cautils.ScanInfo) (cautils.K8SResources, map[string]workloadinterface.IMetadata, cautils.ExternalResources, map[string]bool, error)
	// StreamResourcesBatches streams resources in batches so the evaluation
	// input stays bounded on large clusters (resident batch plus one namespace
	// at a time) and collection is a single pass per GVR.
	// Returns a channel of ResourceBatch objects, the expected number of namespace batches, and an error if streaming setup fails.
	// The caller must process batches sequentially and ensure proper cleanup.
	StreamResourcesBatches(ctx context.Context, sessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) (<-chan *cautils.ResourceBatch, <-chan error, int, error)
	// EstimateClusterSize returns an estimate of the total number of resources in the cluster.
	// For Kubernetes clusters this queries the API server with metadata-only LIST requests.
	// For file-based scans it returns (0, nil).
	// A non-nil error means the estimate could not be produced and the caller should fall back to non-streaming.
	EstimateClusterSize(ctx context.Context, scanInfo *cautils.ScanInfo) (int, error)
	GetClusterAPIServerInfo(ctx context.Context) *version.Info
	GetCloudProvider() string
	// Preflight checks, without collecting any resources, whether the current
	// credentials can list every resource type the given policies require.
	Preflight(ctx context.Context, sessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) (*PreflightResult, error)
}
