package resourcehandler

import (
	"context"
	"errors"
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"k8s.io/apimachinery/pkg/version"
)

// ManifestResourceHandler handles resources from in-memory YAML or JSON manifest content.
type ManifestResourceHandler struct {
	manifestContent []byte
}

var _ IResourceHandler = (*ManifestResourceHandler)(nil)

// NewManifestResourceHandler creates a new ManifestResourceHandler with the provided manifest bytes.
func NewManifestResourceHandler(manifestContent []byte) *ManifestResourceHandler {
	return &ManifestResourceHandler{
		manifestContent: manifestContent,
	}
}

func (h *ManifestResourceHandler) GetResources(ctx context.Context, sessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) (cautils.K8SResources, map[string]workloadinterface.IMetadata, cautils.ExternalResources, map[string]bool, error) {
	allResources := map[string]workloadinterface.IMetadata{}
	externalResources := cautils.ExternalResources{}

	if len(h.manifestContent) == 0 {
		return nil, nil, nil, nil, errors.New("missing manifest input")
	}

	logger.L().Start("Accessing in-memory manifest objects...")

	// Read workloads from in-memory YAML/JSON bytes
	workloads, err := cautils.ReadFile(h.manifestContent, cautils.YAML_FILE_FORMAT)
	if err != nil {
		return nil, allResources, nil, nil, err
	}
	if len(workloads) == 0 {
		return nil, allResources, nil, nil, ErrNoScannableResources
	}

	mappedResources := map[string][]workloadinterface.IMetadata{}
	addWorkloadsToResourcesMap(mappedResources, workloads)

	if sessionObj.ResourceSource == nil {
		sessionObj.ResourceSource = make(map[string]reporthandling.Source)
	}
	for _, wl := range workloads {
		allResources[wl.GetID()] = wl
		sessionObj.ResourceSource[wl.GetID()] = reporthandling.Source{
			RelativePath: "manifest.yaml",
			Path:         "manifest.yaml",
		}
	}

	sessionObj.SingleResourceScan = nil
	selected, err := findScanObjectResource(mappedResources, scanInfo.ScanObject)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if selected != nil {
		workload := workloadinterface.NewWorkloadObj(selected.GetObject())
		sessionObj.SingleResourceScan = workload
		if workloadHasParent(workload.GetObject()) {
			return nil, nil, nil, nil, fmt.Errorf("resource %s has a parent and cannot be scanned", workload.GetID())
		}
	}

	scanningScope := reporthandling.ScopeFile
	if sessionObj.Metadata != nil {
		scanningScope = cautils.GetScanningScope(sessionObj.Metadata.ContextMetadata)
	}
	offlineResolver := newOfflineManifestResourceResolver(mappedResources)
	resourceToQuery, excludedRulesMap := getQueryableResourceMapFromPolicies(sessionObj.Policies, sessionObj.SingleResourceScan, scanningScope, offlineResolver)
	k8sResources := resourceToQuery.ToK8sResourceMap()

	for i := range mappedResources {
		if _, ok := k8sResources[i]; ok {
			var ids []string
			for j := range mappedResources[i] {
				ids = append(ids, mappedResources[i][j].GetID())
				allResources[mappedResources[i][j].GetID()] = mappedResources[i][j]
			}
			k8sResources[i] = append(k8sResources[i], ids...)
		}
	}

	logger.L().StopSuccess("Done accessing in-memory manifest objects")
	addSingleResourceToResourceMaps(k8sResources, allResources, selected, offlineResolver)

	if err := applyKindFilter(k8sResources, allResources, scanInfo, sessionObj.SingleResourceScan); err != nil {
		return nil, nil, nil, nil, err
	}

	return k8sResources, allResources, externalResources, excludedRulesMap, nil
}

func (h *ManifestResourceHandler) StreamResourcesBatches(ctx context.Context, sessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) (<-chan *cautils.ResourceBatch, <-chan error, int, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, 0, err
	}
	batchChan := make(chan *cautils.ResourceBatch, 1)
	errChan := make(chan error, 1)

	k8sResources, allResources, externalResources, excludedRulesMap, err := h.GetResources(ctx, sessionObj, scanInfo)
	if err != nil {
		return nil, nil, 0, err
	}
	sessionObj.ExcludedRules = excludedRulesMap

	go func() {
		defer close(errChan)
		defer close(batchChan)

		batch := cautils.NewResourceBatch(cautils.ClusterScope)
		batch.K8SResources = k8sResources
		batch.AllResources = allResources
		batch.ExternalResources = externalResources

		publishFileResourceBatch(ctx, batchChan, errChan, batch)
	}()

	return batchChan, errChan, 0, nil
}

func (h *ManifestResourceHandler) GetCloudProvider() string {
	return ""
}

func (h *ManifestResourceHandler) Preflight(_ context.Context, _ *cautils.OPASessionObj, _ *cautils.ScanInfo) (*PreflightResult, error) {
	return &PreflightResult{}, nil
}

func (h *ManifestResourceHandler) EstimateClusterSize(_ context.Context, _ *cautils.ScanInfo) (int, error) {
	return 0, nil
}

func (h *ManifestResourceHandler) GetClusterAPIServerInfo(_ context.Context) *version.Info {
	return nil
}
