package resourcehandler

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/cloudsupport"
	cloudapis "github.com/kubescape/k8s-interface/cloudsupport/apis"
	cloudv1 "github.com/kubescape/k8s-interface/cloudsupport/v1"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/metrics"
	"github.com/kubescape/kubescape/v3/core/pkg/hostsensorutils"
	"github.com/kubescape/kubescape/v3/core/pkg/vapreconcile"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8slabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/tools/pager"
)

type cloudResourceGetter func(string, string) (workloadinterface.IMetadata, error)

var cloudResourceGetterMapping = map[string]cloudResourceGetter{
	cloudapis.CloudProviderDescribeKind:                cloudsupport.GetDescriptiveInfoFromCloudProvider,
	cloudapis.CloudProviderDescribeRepositoriesKind:    cloudsupport.GetDescribeRepositoriesFromCloudProvider,
	cloudapis.CloudProviderListEntitiesForPoliciesKind: cloudsupport.GetListEntitiesForPoliciesFromCloudProvider,
	cloudapis.CloudProviderPolicyVersionKind:           cloudsupport.GetPolicyVersionFromCloudProvider,
}

var _ IResourceHandler = &K8sResourceHandler{}

type K8sResourceHandler struct {
	clusterName       string
	cloudProvider     string
	k8s               *k8sinterface.KubernetesApi
	hostSensorHandler hostsensorutils.IHostSensor
	rbacObjectsAPI    *cautils.RBACObjects
}

func NewK8sResourceHandler(ctx context.Context, k8s *k8sinterface.KubernetesApi, hostSensorHandler hostsensorutils.IHostSensor, rbacObjects *cautils.RBACObjects, clusterName string) *K8sResourceHandler {
	k8sHandler := &K8sResourceHandler{
		clusterName:       clusterName,
		k8s:               k8s,
		hostSensorHandler: hostSensorHandler,
		rbacObjectsAPI:    rbacObjects,
	}
	if err := k8sHandler.setCloudProvider(ctx); err != nil {
		logger.L().Warning("failed to set cloud provider", helpers.Error(err))
	}
	return k8sHandler
}

func (k8sHandler *K8sResourceHandler) GetResources(ctx context.Context, sessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) (cautils.K8SResources, map[string]workloadinterface.IMetadata, cautils.ExternalResources, map[string]bool, error) {
	logger.L().Start("Accessing Kubernetes objects...")
	var err error

	globalFieldSelectors := getFieldSelectorFromScanInfo(scanInfo)
	resolver, discoveryFailures := newDiscoveryResourceResolver(k8sHandler.k8s.DiscoveryClient)
	sessionObj.PartialGVRFailures = append(sessionObj.PartialGVRFailures, discoveryFailures...)

	if scanInfo.IsDeletedScanObject {
		sessionObj.SingleResourceScan, err = getWorkloadFromScanObject(scanInfo.ScanObject)
	} else {
		sessionObj.SingleResourceScan, err = k8sHandler.findScanObjectResource(ctx, scanInfo.ScanObject, globalFieldSelectors, resolver)
	}

	if err != nil {
		return nil, nil, nil, nil, err
	}

	scanningScope := cautils.GetScanningScope(sessionObj.Metadata.ContextMetadata)

	resourceToControl := make(map[string][]string)
	// build resources map
	// map resources based on framework required resources: map["/group/version/kind"][]<k8s workloads ids>
	queryableResources, excludedRulesMap := getQueryableResourceMapFromPolicies(sessionObj.Policies, sessionObj.SingleResourceScan, scanningScope, resolver)
	ksResourceMap := setKSResourceMap(sessionObj.Policies, resourceToControl, resolver)

	// map of Kubescape resources to control_ids
	sessionObj.ResourceToControlsMap = resourceToControl

	// pull k8s resources
	k8sResourcesMap, allResources, failedQueries := k8sHandler.pullResources(ctx, queryableResources, globalFieldSelectors)

	// Record failed GVR statuses before any early return so BuildScanCoverage
	// has data even when every pull fails (severe RBAC restrictions).
	// Partial failures (some selectors succeeded for the GVR) are returned
	// separately so they can be surfaced without overriding the whole-GVR status.
	partialFailures := recordFailedQueryStatuses(failedQueries, k8sResourcesMap, sessionObj.InfoMap)
	if len(partialFailures) > 0 {
		sessionObj.PartialGVRFailures = append(sessionObj.PartialGVRFailures, partialFailures...)
		for _, p := range partialFailures {
			logger.L().Ctx(ctx).Warning("partial resource collection: some resources may be missing from scan results",
				helpers.String("gvr", p.GVR),
				helpers.String("selector", p.Selector),
				helpers.String("error", p.Error))
		}
	}

	if len(allResources) == 0 && len(failedQueries) > 0 {
		// Every query failed — nothing was collected; treat as fatal.
		// If the context was cancelled (e.g. scan timeout expired or Ctrl-C),
		// report that explicitly so users understand why the scan stopped rather
		// than seeing a confusing "failed to pull resources" message.
		if ctxErr := ctx.Err(); ctxErr != nil {
			cautils.StopSpinner()
			return k8sResourcesMap, allResources, ksResourceMap, excludedRulesMap, fmt.Errorf("scan aborted: %w", ctxErr)
		}
		var combined []string
		for _, f := range failedQueries {
			combined = append(combined, fmt.Sprintf("%s: %s", f.gvr, f.err.Error()))
		}
		cautils.StopSpinner()
		return k8sResourcesMap, allResources, ksResourceMap, excludedRulesMap, fmt.Errorf("failed to pull any Kubernetes resources: %s", strings.Join(combined, "; "))
	}
	for _, f := range failedQueries {
		logger.L().Ctx(ctx).Warning("failed to pull resource type",
			helpers.String("gvr", f.gvr), helpers.Error(f.err))
	}

	// add single resource to k8s resources map (for single resource scan)
	if !scanInfo.IsDeletedScanObject {
		addSingleResourceToResourceMaps(k8sResourcesMap, allResources, sessionObj.SingleResourceScan, resolver)
	}

	metrics.UpdateKubernetesResourcesCount(ctx, int64(len(allResources)))
	numberOfWorkerNodes, err := k8sHandler.pullWorkerNodesNumber(ctx)

	if err != nil {
		logger.L().Debug("failed to collect worker nodes number", helpers.Error(err))
	} else {
		sessionObj.SetNumberOfWorkerNodes(numberOfWorkerNodes)
		metrics.UpdateWorkerNodesCount(ctx, int64(numberOfWorkerNodes))
	}

	logger.L().StopSuccess("Accessed Kubernetes objects")

	hostResources := cautils.MapHostResources(ksResourceMap)
	// check that controls use host sensor resources
	if len(hostResources) > 0 {
		if sessionObj.Metadata.ScanMetadata.HostScanner {
			logger.L().Info("Requesting Host scanner data")
			cautils.StartSpinner()
			infoMap, err := k8sHandler.collectHostResources(ctx, allResources, ksResourceMap)
			if err != nil {
				logger.L().Ctx(ctx).Warning("failed to collect host scanner resources", helpers.Error(err))
				cautils.SetInfoMapForResources(err.Error(), hostResources, sessionObj.InfoMap)
			} else if k8sHandler.hostSensorHandler == nil {
				// using hostSensor mock
				cautils.SetInfoMapForResources("failed to init host scanner", hostResources, sessionObj.InfoMap)
			} else {
				maps.Copy(sessionObj.InfoMap, infoMap)
			}
			cautils.StopSpinner()
			logger.L().Success("Requested Host scanner data")
		} else {
			cautils.SetInfoMapForResources("This control is scanned exclusively by the Kubescape operator, not the Kubescape CLI. Install the Kubescape operator:\n     https://kubescape.io/docs/install-operator/.", hostResources, sessionObj.InfoMap)
		}
	}

	if err := k8sHandler.collectRbacResources(allResources); err != nil {
		logger.L().Ctx(ctx).Warning("failed to collect rbac resources", helpers.Error(err))
	}
	cloudResources := cautils.MapCloudResources(ksResourceMap)

	setMapNamespaceToNumOfResources(ctx, allResources, sessionObj)

	// check that controls use cloud resources
	if len(cloudResources) > 0 {
		err := k8sHandler.collectCloudResources(ctx, sessionObj, allResources, ksResourceMap, cloudResources)
		if err != nil {
			cautils.SetInfoMapForResources(err.Error(), cloudResources, sessionObj.InfoMap)
			logger.L().Debug("failed to collect cloud data", helpers.Error(err))
		}
	}

	if scanInfo.GetScanningContext() == cautils.ContextCluster {
		policies, bindings, err := vapreconcile.Collect(ctx, k8sHandler.k8s)
		if err != nil {
			logger.L().Ctx(ctx).Warning("failed to collect VAP resources", helpers.Error(err))
		} else {
			sessionObj.VAPPolicies = policies
			sessionObj.VAPBindings = bindings
		}
	}

	return k8sResourcesMap, allResources, ksResourceMap, excludedRulesMap, nil
}

func (k8sHandler *K8sResourceHandler) GetCloudProvider() string {
	return k8sHandler.cloudProvider
}

// StreamResourcesBatches streams resources in batches so the OPA processor can
// evaluate one namespace batch at a time, bounding the evaluation input instead
// of holding the whole cluster in it. This method implements a two-phase
// approach:
// 1. First, it collects all cluster-scoped and external resources into a resident batch
// 2. Then, it streams namespace-scoped resources in batches
// The resident batch is sent first, followed by namespace batches in sorted order.
// The producer goroutine never mutates sessionObj's K8SResources,
// ExternalResources, or AllResources — the collected maps are carried on the
// resident batch and copied into the session by ProcessWithStreaming once it
// receives the batch, so NewOPAProcessor (which runs concurrently with the
// producer) never reads maps another goroutine is writing.
// Returns the batch channel, error channel, expected number of namespace batches, and any setup error.
func (k8sHandler *K8sResourceHandler) StreamResourcesBatches(ctx context.Context, sessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) (<-chan *cautils.ResourceBatch, <-chan error, int, error) {
	logger.L().Start("Streaming Kubernetes objects in batches...")

	batchChan := make(chan *cautils.ResourceBatch, 2)
	errChan := make(chan error, 1)

	// Setup phase: collect metadata and queryable resources
	globalFieldSelectors := getFieldSelectorFromScanInfo(scanInfo)
	resolver, discoveryFailures := newDiscoveryResourceResolver(k8sHandler.k8s.DiscoveryClient)
	sessionObj.PartialGVRFailures = append(sessionObj.PartialGVRFailures, discoveryFailures...)

	var setupErr error
	if scanInfo.IsDeletedScanObject {
		sessionObj.SingleResourceScan, setupErr = getWorkloadFromScanObject(scanInfo.ScanObject)
	} else {
		sessionObj.SingleResourceScan, setupErr = k8sHandler.findScanObjectResource(ctx, scanInfo.ScanObject, globalFieldSelectors, resolver)
	}

	if setupErr != nil {
		return nil, nil, 0, setupErr
	}

	scanningScope := cautils.GetScanningScope(sessionObj.Metadata.ContextMetadata)
	resourceToControl := make(map[string][]string)
	queryableResources, excludedRulesMap := getQueryableResourceMapFromPolicies(sessionObj.Policies, sessionObj.SingleResourceScan, scanningScope, resolver)
	ksResourceMap := setKSResourceMap(sessionObj.Policies, resourceToControl, resolver)
	sessionObj.ResourceToControlsMap = resourceToControl
	sessionObj.ExcludedRules = excludedRulesMap

	// Compute expected namespace count synchronously before launching
	// the goroutine so the caller has it at return time.
	expectedNamespaceBatches := k8sHandler.countNamespaces(ctx, scanInfo)

	// Start streaming goroutine
	go func() {
		defer close(errChan)
		defer close(batchChan)
		defer logger.L().StopSuccess("Done streaming Kubernetes objects")

		if err := k8sHandler.collectAndStreamBatches(ctx, queryableResources, globalFieldSelectors, sessionObj, scanInfo, ksResourceMap, batchChan, resolver); err != nil {
			errChan <- err
			return
		}
	}()

	return batchChan, errChan, expectedNamespaceBatches, nil
}

// collectAndStreamBatches pulls every queryable GVR exactly once, partitions
// the results into a single resident batch (cluster-scoped and external
// resources) and one batch per namespace, then streams the resident batch
// followed by each namespace batch in deterministic order.
//
// This replaces the previous two-phase approach (collectResidentBatch +
// streamNamespaceBatches) which re-listed every GVR once per namespace,
// resulting in O(L × N) API-server LIST calls on large clusters.
//
// What this bounds is the evaluation input, not the collection peak: every GVR
// is pulled and partitioned before the first batch is sent, so the whole
// cluster is resident in this function at that point. The consumer
// (OPAProcessor.ProcessWithStreaming) evaluates one namespace batch at a time,
// so only the resident batch plus one namespace batch are in the evaluation
// input at any moment. Bounding the collection peak itself would require paged
// LISTs (metav1.ListOptions{Limit, Continue}) per GVR — a larger change than
// this one.
func (k8sHandler *K8sResourceHandler) collectAndStreamBatches(ctx context.Context, queryableResources QueryableResources, globalFieldSelectors IFieldSelector, sessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo, ksResourceMap cautils.ExternalResources, batchChan chan<- *cautils.ResourceBatch, resolver resourceResolver) error {
	resident := cautils.NewResourceBatch(cautils.ClusterScope)
	namespaceBatches := make(map[string]*cautils.ResourceBatch)
	collectedK8sResources := queryableResources.ToK8sResourceMap()
	failedQueries := make(map[string]queryFailure)
	collectedAnyResource := false

	// Single pass: pull each GVR once, partition by scope.
	for key := range queryableResources {
		qr := queryableResources[key]
		apiGroup, apiVersion, resource := k8sinterface.StringToResourceGroup(qr.GroupVersionResourceTriplet)
		gvr := schema.GroupVersionResource{Group: apiGroup, Version: apiVersion, Resource: resource}

		result, selectorErrs := k8sHandler.pullSingleResource(ctx, &gvr, nil, qr.FieldSelectors, globalFieldSelectors, qr.Namespaced)
		for _, se := range selectorErrs {
			// Match the eager collection path: controls may reference optional
			// CRDs which are not installed, so a missing resource is not a scan
			// coverage failure.
			if strings.Contains(se.err.Error(), "the server could not find the requested resource") {
				continue
			}
			qualifiedKey := qr.GroupVersionResourceTriplet + "/" + se.selector
			failedQueries[qualifiedKey] = queryFailure{
				gvr:      qr.GroupVersionResourceTriplet,
				selector: se.selector,
				err:      se.err,
			}
		}
		if len(result) == 0 && len(selectorErrs) > 0 {
			continue
		}

		metaObjs := ConvertMapListToMeta(k8sinterface.ConvertUnstructuredSliceToMap(result))
		if len(metaObjs) > 0 {
			// recordFailedQueryStatuses only distinguishes an empty GVR from a
			// non-empty one. Keep one representative ID instead of duplicating
			// every ID already retained in the streaming batches.
			collectedK8sResources[qr.GroupVersionResourceTriplet] = []string{metaObjs[0].GetID()}
			collectedAnyResource = true
		}

		for _, metaObj := range metaObjs {
			scope := cautils.ResourceScope(metaObj)
			if scope == cautils.ClusterScope {
				resident.K8SResources[qr.GroupVersionResourceTriplet] = append(resident.K8SResources[qr.GroupVersionResourceTriplet], metaObj.GetID())
				resident.AllResources[metaObj.GetID()] = metaObj
			} else {
				batch, ok := namespaceBatches[scope]
				if !ok {
					batch = cautils.NewResourceBatch(scope)
					namespaceBatches[scope] = batch
				}
				batch.K8SResources[qr.GroupVersionResourceTriplet] = append(batch.K8SResources[qr.GroupVersionResourceTriplet], metaObj.GetID())
				batch.AllResources[metaObj.GetID()] = metaObj
			}
		}
	}

	// Preserve the eager collector's failure contract. Whole-GVR failures feed
	// InfoMap, while selector failures for a GVR that returned some resources
	// remain non-fatal and are surfaced as partial coverage.
	partialFailures := recordFailedQueryStatuses(failedQueries, collectedK8sResources, sessionObj.InfoMap)
	if len(partialFailures) > 0 {
		sessionObj.PartialGVRFailures = append(sessionObj.PartialGVRFailures, partialFailures...)
		for _, p := range partialFailures {
			logger.L().Ctx(ctx).Warning("partial resource collection: some resources may be missing from scan results",
				helpers.String("gvr", p.GVR),
				helpers.String("selector", p.Selector),
				helpers.String("error", p.Error))
		}
	}
	if !collectedAnyResource && len(failedQueries) > 0 {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("scan aborted: %w", ctxErr)
		}
		var combined []string
		for _, f := range failedQueries {
			combined = append(combined, fmt.Sprintf("%s: %s", f.gvr, f.err.Error()))
		}
		return fmt.Errorf("failed to pull any Kubernetes resources: %s", strings.Join(combined, "; "))
	}
	for _, f := range failedQueries {
		logger.L().Ctx(ctx).Warning("failed to pull resource type",
			helpers.String("gvr", f.gvr), helpers.Error(f.err))
	}

	// Collect external resources (host, cloud, RBAC, VAP) into the resident batch.
	allResources := resident.AllResources

	if !scanInfo.IsDeletedScanObject && sessionObj.SingleResourceScan != nil {
		addSingleResourceToResourceMaps(resident.K8SResources, allResources, sessionObj.SingleResourceScan, resolver)
	}

	hostResources := cautils.MapHostResources(ksResourceMap)
	if len(hostResources) > 0 && sessionObj.Metadata.ScanMetadata.HostScanner {
		logger.L().Info("Requesting Host scanner data")
		infoMap, err := k8sHandler.collectHostResources(ctx, allResources, ksResourceMap)
		if err != nil {
			logger.L().Ctx(ctx).Warning("failed to collect host scanner resources", helpers.Error(err))
			cautils.SetInfoMapForResources(err.Error(), hostResources, sessionObj.InfoMap)
		} else {
			for k, v := range infoMap {
				sessionObj.InfoMap[k] = v
			}
		}
	}

	if err := k8sHandler.collectRbacResources(allResources); err != nil {
		logger.L().Ctx(ctx).Warning("failed to collect rbac resources", helpers.Error(err))
	}

	cloudResources := cautils.MapCloudResources(ksResourceMap)
	if len(cloudResources) > 0 {
		if err := k8sHandler.collectCloudResources(ctx, sessionObj, allResources, ksResourceMap, cloudResources); err != nil {
			cautils.SetInfoMapForResources(err.Error(), cloudResources, sessionObj.InfoMap)
		}
	}

	if scanInfo.GetScanningContext() == cautils.ContextCluster {
		policies, bindings, err := vapreconcile.Collect(ctx, k8sHandler.k8s)
		if err != nil {
			logger.L().Ctx(ctx).Warning("failed to collect VAP resources", helpers.Error(err))
		} else {
			sessionObj.VAPPolicies = policies
			sessionObj.VAPBindings = bindings
		}
	}

	for groupResource, ids := range ksResourceMap {
		for _, id := range ids {
			if _, ok := allResources[id]; ok {
				resident.ExternalResources[groupResource] = append(resident.ExternalResources[groupResource], id)
			}
		}
	}

	// Note: the resident batch deliberately carries K8SResources,
	// ExternalResources, and AllResources instead of the producer writing them
	// to sessionObj. This goroutine runs concurrently with the caller's
	// NewOPAProcessor, which snapshots len(sessionObj.AllResources) at
	// construction; writing those fields here would be an unsynchronised
	// concurrent write against that read. ProcessWithStreaming copies the
	// resident batch into the processor (sessionObj) after receiving it, so the
	// maps still land on the session by the time downstream stages run.

	numberOfWorkerNodes, err := k8sHandler.pullWorkerNodesNumber(ctx)
	if err != nil {
		logger.L().Debug("failed to collect worker nodes number", helpers.Error(err))
	} else {
		sessionObj.SetNumberOfWorkerNodes(numberOfWorkerNodes)
		metrics.UpdateKubernetesResourcesCount(ctx, int64(len(allResources)))
		metrics.UpdateWorkerNodesCount(ctx, int64(numberOfWorkerNodes))
	}

	// Stream resident batch first.
	select {
	case batchChan <- resident:
	case <-ctx.Done():
		return ctx.Err()
	}

	// Stream namespace batches in deterministic order.
	sortedNamespaces := make([]string, 0, len(namespaceBatches))
	for ns := range namespaceBatches {
		sortedNamespaces = append(sortedNamespaces, ns)
	}
	sort.Strings(sortedNamespaces)
	for _, ns := range sortedNamespaces {
		select {
		case batchChan <- namespaceBatches[ns]:
		case <-ctx.Done():
			return ctx.Err()
		}
		// Drop the producer's reference to the batch now that it has been
		// handed off. This bounds the producer's retention during drain when
		// the consumer is slower than the producer; it is not a peak-memory
		// reduction — the resources stay reachable via the consumer's
		// AllResources for downstream stages.
		delete(namespaceBatches, ns)
	}

	return nil
}

// findScanObjectResource pulls the requested k8s object to be scanned from the api server
func (k8sHandler *K8sResourceHandler) findScanObjectResource(ctx context.Context, resource *objectsenvelopes.ScanObject, globalFieldSelector IFieldSelector, resolver resourceResolver) (workloadinterface.IWorkload, error) {
	if resource == nil {
		return nil, nil
	}

	logger.L().Debug("Single resource scan", helpers.String("resource", resource.GetID()))

	var resolved []resolvedResource
	if resource.GetApiVersion() == "" {
		// Keep the legacy single-resource behavior for built-in objects whose
		// callers omit apiVersion. CRDs still require their declared apiVersion
		// so discovery can select an unambiguous GVR.
		groupVersionResource, err := k8sinterface.GetGroupVersionResource(resource.GetKind())
		if err == nil {
			resolved = []resolvedResource{{
				groupVersionResourceTriplet: k8sinterface.GroupVersionResourceToString(&groupVersionResource),
			}}
		} else {
			return nil, fmt.Errorf("apiVersion is required to resolve non-built-in resource %q for a single-resource scan", resource.GetKind())
		}
	} else {
		g, v := k8sinterface.SplitApiVersion(resource.GetApiVersion())
		resolved = resolver(g, v, resource.GetKind())
	}
	if len(resolved) != 1 {
		return nil, fmt.Errorf("resource not found in Kubernetes discovery: %s", getReadableID(resource))
	}
	apiGroup, apiVersion, resourceName := k8sinterface.StringToResourceGroup(resolved[0].groupVersionResourceTriplet)
	gvr := schema.GroupVersionResource{Group: apiGroup, Version: apiVersion, Resource: resourceName}

	fieldSelectors := getNameFieldSelectorString(resource.GetName(), FieldSelectorsEqualsOperator)
	if resource.GetNamespace() != "" && ((resolved[0].namespaced != nil && *resolved[0].namespaced) || (resolved[0].namespaced == nil && k8sinterface.IsNamespaceScope(&gvr))) {
		fieldSelectors = combineFieldSelectors(fieldSelectors, getNamespaceFieldSelectorString(resource.GetNamespace(), FieldSelectorsEqualsOperator))
	}
	result, selectorErrs := k8sHandler.pullSingleResource(ctx, &gvr, nil, fieldSelectors, globalFieldSelector, resolved[0].namespaced)
	if len(result) == 0 && len(selectorErrs) > 0 {
		return nil, fmt.Errorf("failed to get resource %s, reason: %v", getReadableID(resource), selectorErrs[0].err)
	}
	for _, se := range selectorErrs {
		logger.L().Warning("partial collection during single resource scan",
			helpers.String("resource", getReadableID(resource)),
			helpers.String("selector", se.selector),
			helpers.Error(se.err))
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("resource %s was not found", getReadableID(resource))
	}

	metaObjs := ConvertMapListToMeta(k8sinterface.ConvertUnstructuredSliceToMap(result))
	if len(metaObjs) == 0 {
		return nil, fmt.Errorf("resource %s has a parent and cannot be scanned", getReadableID(resource))
	}

	if len(metaObjs) > 1 {
		return nil, fmt.Errorf("more than one resource found for %s", getReadableID(resource))
	}

	if !k8sinterface.IsTypeWorkload(metaObjs[0].GetObject()) {
		return nil, fmt.Errorf("%s is not a valid Kubernetes workload", getReadableID(resource))
	}

	wl := workloadinterface.NewWorkloadObj(metaObjs[0].GetObject())
	return wl, nil
}

func (k8sHandler *K8sResourceHandler) collectCloudResources(ctx context.Context, sessionObj *cautils.OPASessionObj, allResources map[string]workloadinterface.IMetadata, externalResourceMap cautils.ExternalResources, cloudResources []string) error {

	if k8sHandler.cloudProvider == "" {
		return fmt.Errorf("failed to get cloud provider, cluster: %s", k8sHandler.clusterName)
	}

	logger.L().Start("Downloading cloud resources...")

	if sessionObj.Metadata != nil && sessionObj.Metadata.ContextMetadata.ClusterContextMetadata != nil {
		sessionObj.Metadata.ContextMetadata.ClusterContextMetadata.CloudProvider = k8sHandler.cloudProvider
	}

	logger.L().Debug("cloud", helpers.String("clusterName", k8sHandler.clusterName), helpers.String("provider", k8sHandler.cloudProvider))

	for resourceKind, resourceGetter := range cloudResourceGetterMapping {
		if !cloudResourceRequired(cloudResources, resourceKind) {
			continue
		}

		logger.L().Debug("Collecting cloud data ", helpers.String("resourceKind", resourceKind))
		wl, err := resourceGetter(k8sHandler.clusterName, k8sHandler.cloudProvider)
		if err != nil {
			switch {
			case strings.Contains(err.Error(), cloudv1.NotSupportedMsg):
				// silently skip unsupported providers
			case errors.Is(err, cloudsupport.ErrCloudDescribeUnavailable):
				logger.L().Debug("cloud describe unavailable, continuing scan", helpers.String("resourceKind", resourceKind), helpers.Error(err))
				cautils.SetInfoMapForResources("cloud-describe-unavailable", cloudResources, sessionObj.InfoMap)
			default:
				logger.L().Debug("failed to get cloud data", helpers.String("resourceKind", resourceKind), helpers.Error(err))
				err = fmt.Errorf("failed to get %s descriptive information. Read more: https://kubescape.io/docs/integrations/kubescape-integration-with-cloud-providers/", strings.ToUpper(k8sHandler.cloudProvider))
				cautils.SetInfoMapForResources(err.Error(), cloudResources, sessionObj.InfoMap)
			}

			continue
		}

		allResources[wl.GetID()] = wl
		externalResourceMap[fmt.Sprintf("%s/%s", wl.GetApiVersion(), wl.GetKind())] = []string{wl.GetID()}
	}
	logger.L().StopSuccess("Downloaded cloud resources")

	// get api server info resource
	if cloudResourceRequired(cloudResources, string(cloudsupport.TypeApiServerInfo)) {
		if err := k8sHandler.collectAPIServerInfoResource(allResources, externalResourceMap); err != nil {
			logger.L().Ctx(ctx).Warning("failed to collect api server info resource", helpers.Error(err))

			return err
		}
	}

	return nil
}

func cloudResourceRequired(cloudResources []string, resource string) bool {
	for _, cresource := range cloudResources {
		if strings.Contains(cresource, resource) {
			return true
		}
	}
	return false
}

func (k8sHandler *K8sResourceHandler) collectAPIServerInfoResource(allResources map[string]workloadinterface.IMetadata, externalResourceMap cautils.ExternalResources) error {
	clusterAPIServerInfo, err := k8sHandler.k8s.DiscoveryClient.ServerVersion()
	if err != nil {
		return err
	}
	resource := cloudsupport.NewApiServerVersionInfo(clusterAPIServerInfo)
	allResources[resource.GetID()] = resource
	externalResourceMap[fmt.Sprintf("%s/%s", resource.GetApiVersion(), resource.GetKind())] = []string{resource.GetID()}

	return nil
}

func (k8sHandler *K8sResourceHandler) GetClusterAPIServerInfo(ctx context.Context) *version.Info {
	clusterAPIServerInfo, err := k8sHandler.k8s.DiscoveryClient.ServerVersion()
	if err != nil {
		logger.L().Ctx(ctx).Warning("failed to discover API server information", helpers.Error(err))
		return nil
	}
	return clusterAPIServerInfo
}

// set  namespaceToNumOfResources map in report
func setMapNamespaceToNumOfResources(ctx context.Context, allResources map[string]workloadinterface.IMetadata, sessionObj *cautils.OPASessionObj) {

	mapNamespaceToNumberOfResources := make(map[string]int)
	for _, resource := range allResources {
		if obj := workloadinterface.NewWorkloadObj(resource.GetObject()); obj != nil {
			ownerReferences, err := obj.GetOwnerReferences()
			if err == nil {
				// Add an object to the map if the object does not have a parent but is contained within a namespace (except Job)
				if len(ownerReferences) == 0 {
					if ns := resource.GetNamespace(); ns != "" {
						if obj.GetKind() != "Job" {
							mapNamespaceToNumberOfResources[ns]++
						}
					}
				}
			} else {
				logger.L().Ctx(ctx).Warning(fmt.Sprintf("failed to get owner references. Resource %s will not be counted", obj.GetName()), helpers.Error(err))
			}
		}
	}
	sessionObj.SetMapNamespaceToNumberOfResources(mapNamespaceToNumberOfResources)
}

// queryFailure records a failed pull at query granularity (GVR + field selectors).
type queryFailure struct {
	gvr      string
	selector string // the field selector that failed; empty for whole-GVR failures
	err      error
}

// selectorFailure records a single per-field-selector LIST error inside pullSingleResource.
type selectorFailure struct {
	selector string
	err      error
}

const maxParallelResourcePulls = 8

func (k8sHandler *K8sResourceHandler) pullResources(ctx context.Context, queryableResources QueryableResources, globalFieldSelectors IFieldSelector) (cautils.K8SResources, map[string]workloadinterface.IMetadata, map[string]queryFailure) {
	k8sResources := queryableResources.ToK8sResourceMap()
	allResources := map[string]workloadinterface.IMetadata{}

	failedQueries := map[string]queryFailure{}

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)

	sem := make(chan struct{}, maxParallelResourcePulls)

	for key := range queryableResources {
		qr := queryableResources[key]
		wg.Add(1)
		go func(qr QueryableResource) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				mu.Lock()
				failedQueries[qr.GroupVersionResourceTriplet] = queryFailure{
					gvr: qr.GroupVersionResourceTriplet,
					err: ctx.Err(),
				}
				mu.Unlock()
				return
			}
			defer func() { <-sem }()

			apiGroup, apiVersion, resource := k8sinterface.StringToResourceGroup(qr.GroupVersionResourceTriplet)
			gvr := schema.GroupVersionResource{Group: apiGroup, Version: apiVersion, Resource: resource}
			result, selectorErrs := k8sHandler.pullSingleResource(ctx, &gvr, nil, qr.FieldSelectors, globalFieldSelectors, qr.Namespaced)
			if err := ctx.Err(); err != nil {
				mu.Lock()
				failedQueries[qr.GroupVersionResourceTriplet] = queryFailure{
					gvr: qr.GroupVersionResourceTriplet,
					err: err,
				}
				mu.Unlock()
				return
			}

			if len(selectorErrs) > 0 {
				mu.Lock()
				for _, se := range selectorErrs {
					if strings.Contains(se.err.Error(), "the server could not find the requested resource") {
						continue
					}
					qualifiedKey := qr.GroupVersionResourceTriplet + "/" + se.selector
					failedQueries[qualifiedKey] = queryFailure{
						gvr:      qr.GroupVersionResourceTriplet,
						selector: se.selector,
						err:      se.err,
					}
				}
				mu.Unlock()
			}

			if len(result) == 0 && len(selectorErrs) > 0 {
				return
			}

			metaObjs := ConvertMapListToMeta(k8sinterface.ConvertUnstructuredSliceToMap(result))
			ids := workloadinterface.ListMetaIDs(metaObjs)

			mu.Lock()
			for j := range metaObjs {
				allResources[metaObjs[j].GetID()] = metaObjs[j]
			}
			gvrKey := qr.GroupVersionResourceTriplet
			if _, ok := k8sResources[gvrKey]; !ok {
				k8sResources[gvrKey] = ids
			} else {
				k8sResources[gvrKey] = append(k8sResources[gvrKey], ids...)
			}
			mu.Unlock()
		}(qr)
	}

	wg.Wait()
	return k8sResources, allResources, failedQueries
}

func recordFailedQueryStatuses(failedQueries map[string]queryFailure, k8sResources cautils.K8SResources, infoMap map[string]apis.StatusInfo) []cautils.PartialGVRPull {
	var partials []cautils.PartialGVRPull
	for _, f := range failedQueries {
		if len(k8sResources[f.gvr]) > 0 {
			partials = append(partials, cautils.PartialGVRPull{
				GVR:      f.gvr,
				Selector: f.selector,
				Error:    f.err.Error(),
			})
			continue
		}
		infoMap[f.gvr] = apis.StatusInfo{
			InnerInfo:   f.err.Error(),
			InnerStatus: apis.StatusSkipped,
			SubStatus:   apis.SubStatusNotEvaluated,
		}
	}
	return partials
}

func (k8sHandler *K8sResourceHandler) pullSingleResource(ctx context.Context, resource *schema.GroupVersionResource, labels map[string]string, fields string, fieldSelector IFieldSelector, namespaced *bool) ([]unstructured.Unstructured, []selectorFailure) {
	var resourceList []unstructured.Unstructured
	var selectorErrs []selectorFailure

	fieldSelectors := fieldSelector.GetNamespacesSelectors(resource, namespaced)

	for i := range fieldSelectors {
		listOptions := metav1.ListOptions{}

		if len(labels) > 0 {
			set := k8slabels.Set(labels)
			listOptions.LabelSelector = set.AsSelector().String()
		}

		if fieldSelectors[i] != "" {
			listOptions.FieldSelector = combineFieldSelectors(fieldSelectors[i], fields)
		} else if fields != "" {
			listOptions.FieldSelector = fields
		} else {
			listOptions.FieldSelector = ""
		}

		clientResource := k8sHandler.k8s.DynamicClient.Resource(*resource)

		lenBefore := len(resourceList)

		if err := pager.New(func(pCtx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
			return clientResource.List(pCtx, opts)
		}).EachListItem(ctx, listOptions, func(obj runtime.Object) error {

			uObject := obj.(*unstructured.Unstructured)

			if k8sinterface.IsTypeWorkload(uObject.Object) &&
				k8sinterface.WorkloadHasParent(workloadinterface.NewWorkloadObj(uObject.Object)) {

				logger.L().Debug(
					"Skipping resource with parent",
					helpers.String("resource", resource.String()),
					helpers.String("namespace", uObject.GetNamespace()),
					helpers.String("name", uObject.GetName()),
				)

				return nil
			}

			resourceList = append(resourceList, *obj.(*unstructured.Unstructured))
			return nil

		}); err != nil {
			selectorErrs = append(selectorErrs, selectorFailure{
				selector: listOptions.FieldSelector,
				err:      fmt.Errorf("failed to get resource: %v, labelSelector: %v, fieldSelector: %v, reason: %w", resource, listOptions.LabelSelector, listOptions.FieldSelector, err),
			})
			logger.L().Warning("failed to list resource for selector",
				helpers.String("resource", resource.String()),
				helpers.String("fieldSelector", listOptions.FieldSelector),
				helpers.Error(err))
			continue
		}

		logger.L().Debug(
			"Pulled resources",
			helpers.String("resource", resource.String()),
			helpers.String("fieldSelector", listOptions.FieldSelector),
			helpers.String("labelSelector", listOptions.LabelSelector),
			helpers.Int("count", len(resourceList)-lenBefore),
		)
	}

	return resourceList, selectorErrs
}
func ConvertMapListToMeta(resourceMap []map[string]any) []workloadinterface.IMetadata {
	var workloads []workloadinterface.IMetadata
	for i := range resourceMap {
		r := resourceMap[i]
		if w := objectsenvelopes.NewObject(r); w != nil {
			workloads = append(workloads, w)
		}
	}
	return workloads
}

func (k8sHandler *K8sResourceHandler) collectHostResources(ctx context.Context, allResources map[string]workloadinterface.IMetadata, externalResourceMap cautils.ExternalResources) (map[string]apis.StatusInfo, error) {
	logger.L().Debug("Collecting host scanner resources")
	hostResources, infoMap, err := k8sHandler.hostSensorHandler.CollectResources(ctx)
	if err != nil {
		return nil, err
	}

	for rscIdx := range hostResources {
		g, v := getGroupNVersion(hostResources[rscIdx].GetApiVersion())
		allResources[hostResources[rscIdx].GetID()] = &hostResources[rscIdx]

		// Use ResourceGroupToString (not JoinResourceTriplets) to match the key format used by
		// setKSResourceMap: when the host sensor CRD exists in the cluster, IsKindKubernetes returns
		// true and ResourceGroupToString normalizes the kind to lowercase+plural ("kubeletinfos").
		groupResources := k8sinterface.ResourceGroupToString(g, v, hostResources[rscIdx].GetKind())
		for _, groupResource := range groupResources {
			grpResourceList, ok := externalResourceMap[groupResource]
			if !ok {
				grpResourceList = make([]string, 0)
			}
			externalResourceMap[groupResource] = append(grpResourceList, hostResources[rscIdx].GetID())
		}
	}
	return infoMap, nil
}

func (k8sHandler *K8sResourceHandler) collectRbacResources(allResources map[string]workloadinterface.IMetadata) error {
	if k8sHandler.rbacObjectsAPI == nil {
		return nil
	}

	logger.L().Start("Collecting RBAC resources...")
	allRbacResources, err := k8sHandler.rbacObjectsAPI.ListAllResources()
	if err != nil {
		return err
	}
	maps.Copy(allResources, allRbacResources)

	logger.L().StopSuccess("Collected RBAC resources")

	return nil
}

// countNamespaces returns the number of namespaces that can contribute a
// namespace batch to the streaming scan, used as the expected-batch count for
// progress reporting. It honours the scan's include/exclude namespace filters
// (mirroring skipNamespace in the OPA processor: include takes precedence).
// The result is deliberately an upper bound: a namespace batch is only created
// once a namespace actually holds a queryable resource, so sparse or filtered
// clusters progress faster than the estimate suggests.
func (k8sHandler *K8sResourceHandler) countNamespaces(ctx context.Context, scanInfo *cautils.ScanInfo) int {
	if k8sHandler.k8s == nil || k8sHandler.k8s.KubernetesClient == nil {
		return 0
	}
	nsList, err := k8sHandler.k8s.KubernetesClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.L().Ctx(ctx).Debug("failed to list namespaces for progress estimate", helpers.Error(err))
		return 0
	}

	include := splitNamespaces(scanInfo.IncludeNamespaces)
	exclude := splitNamespaces(scanInfo.ExcludedNamespaces)

	count := 0
	for _, ns := range nsList.Items {
		if len(include) > 0 {
			if !slices.Contains(include, ns.Name) {
				continue
			}
		} else if slices.Contains(exclude, ns.Name) {
			continue
		}
		count++
	}
	return count
}

// splitNamespaces parses a comma-separated namespace list (as passed to
// --include-namespaces / --exclude-namespaces) into a clean slice. Empty
// entries and surrounding whitespace are dropped.
func splitNamespaces(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (k8sHandler *K8sResourceHandler) pullWorkerNodesNumber(ctx context.Context) (int, error) {
	nodesList, err := k8sHandler.k8s.KubernetesClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	scheduableNodes := v1.NodeList{}
	if nodesList != nil {
		for _, node := range nodesList.Items {
			if len(node.Spec.Taints) == 0 {
				scheduableNodes.Items = append(scheduableNodes.Items, node)
			} else {
				if !isMasterNodeTaints(node.Spec.Taints) {
					scheduableNodes.Items = append(scheduableNodes.Items, node)
				}
			}
		}
	}
	if err != nil {
		return 0, err
	}
	return len(scheduableNodes.Items), nil
}

// namespacedResourcesToEstimate is the set of common namespaced GVRs used to
// estimate cluster size. These cover the vast majority of resources in a
// typical cluster and keep the estimate cheap (one limit=1 LIST per type).
var namespacedResourcesToEstimate = []schema.GroupVersionResource{
	{Group: "", Version: "v1", Resource: "pods"},
	{Group: "", Version: "v1", Resource: "services"},
	{Group: "", Version: "v1", Resource: "configmaps"},
	{Group: "", Version: "v1", Resource: "secrets"},
	{Group: "", Version: "v1", Resource: "serviceaccounts"},
	{Group: "", Version: "v1", Resource: "persistentvolumeclaims"},
	{Group: "apps", Version: "v1", Resource: "deployments"},
	{Group: "apps", Version: "v1", Resource: "replicasets"},
	{Group: "apps", Version: "v1", Resource: "statefulsets"},
	{Group: "apps", Version: "v1", Resource: "daemonsets"},
	{Group: "batch", Version: "v1", Resource: "jobs"},
	{Group: "batch", Version: "v1", Resource: "cronjobs"},
	{Group: "networking.k8s.io", Version: "v1", Resource: "ingresses"},
	{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
	{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles"},
	{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "rolebindings"},
}

// EstimateClusterSize estimates the number of namespaced resources in the
// cluster by issuing metadata-only LIST requests (limit=1) to the API server
// and summing the remainingItemCount from each response. A per-GVR failure
// (type unavailable, or the service account lacking read access) is tolerated,
// but if no representative type can be listed at all the estimate is useless —
// returning (0, nil) would be indistinguishable from a genuinely small cluster
// — so the function reports the failure and lets the caller fall back to
// non-streaming.
func (k8sHandler *K8sResourceHandler) EstimateClusterSize(ctx context.Context, scanInfo *cautils.ScanInfo) (int, error) {
	if k8sHandler.k8s == nil || k8sHandler.k8s.DynamicClient == nil {
		return 0, fmt.Errorf("kubernetes client not available")
	}

	var total int
	var ok int
	for _, gvr := range namespacedResourcesToEstimate {
		result, err := k8sHandler.k8s.DynamicClient.Resource(gvr).Namespace("").List(ctx, metav1.ListOptions{Limit: 1})
		if err != nil {
			continue
		}
		ok++
		if rc := result.GetRemainingItemCount(); rc != nil {
			total += int(*rc)
		}
	}

	if ok == 0 {
		return 0, fmt.Errorf("no resource types could be listed for cluster size estimate")
	}

	return total, nil
}

func (k8sHandler *K8sResourceHandler) setCloudProvider(ctx context.Context) error {
	nodeList, err := k8sHandler.k8s.KubernetesClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	k8sHandler.cloudProvider = cloudsupport.GetCloudProvider(nodeList)
	return nil
}

// NoSchedule taint with empty value is usually applied to controlplane
func isMasterNodeTaints(taints []v1.Taint) bool {
	for _, taint := range taints {
		if taint.Effect != v1.TaintEffectNoSchedule {
			continue
		}
		switch taint.Key {
		case "node-role.kubernetes.io/master",
			"node-role.kubernetes.io/control-plane":
			return true
		}
	}

	return false
}
