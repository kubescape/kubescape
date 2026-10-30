package resourcehandler

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/core/pkg/clustercomponents"
	"github.com/kubescape/kubescape/v4/core/pkg/componentvulns"
	"github.com/kubescape/kubescape/v4/core/pkg/k8scveindex"
	"github.com/kubescape/kubescape/v4/pkg/imagescan"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
)

const singleResourceComponentVulnInfo = "cluster components are not assessed when scanning a single resource"

type componentVulnSources struct {
	matcher componentvulns.Matcher
	dbBuilt time.Time
	index   *k8scveindex.Index
	close   func()
}

// loadComponentVulnSources opens the vulnerability DB with the same settings
// as image scanning. The applicability index is optional: without it the
// builder reports Kubernetes components as gaps.
func loadComponentVulnSources(ctx context.Context, scanInfo *cautils.ScanInfo) (componentVulnSources, error) {
	failOnStale, maxDBAge := imagescan.ResolveDBAgeGate(scanInfo.FailOnStaleDB, scanInfo.FailOnStaleDBSet, scanInfo.MaxDBAge, scanInfo.MaxDBAgeSet)
	distCfg, installCfg, shouldUpdate, err := imagescan.NewDefaultDBConfig(scanInfo.ListingURL, scanInfo.SkipDBUpdate, failOnStale)
	if err != nil {
		return componentVulnSources{}, fmt.Errorf("invalid Grype database URL %q: %w", scanInfo.ListingURL, err)
	}
	svc, err := imagescan.NewScanServiceWithMatchersAndSources(distCfg, installCfg, scanInfo.UseDefaultMatchers, nil, shouldUpdate)
	if err != nil {
		return componentVulnSources{}, fmt.Errorf("failed to load vulnerability database: %w", err)
	}
	if err := imagescan.EnforceDBAge(svc, shouldUpdate, failOnStale, maxDBAge); err != nil {
		svc.Close()
		return componentVulnSources{}, err
	}

	sources := componentVulnSources{matcher: svc, close: svc.Close}
	if status := svc.VulnDBStatus(); status != nil {
		sources.dbBuilt = status.Built
	}
	index, _, err := k8scveindex.Load(ctx, k8scveindex.Options{SkipUpdate: scanInfo.SkipDBUpdate})
	if err != nil {
		logger.L().Ctx(ctx).Warning("failed to load the Kubernetes CVE applicability index", helpers.Error(err))
	}
	sources.index = index
	return sources, nil
}

// requiredComponentVulnKinds returns the component vulnerability kinds that
// back an effective selected control and pass the kind filters, keyed by their
// resource triplet.
func requiredComponentVulnKinds(sessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo, ksResourceMap cautils.ExternalResources) map[componentvulns.Kind]string {
	allowed := effectiveHostGapAllowlist(sessionObj)
	filters := newKindFilters(scanInfo)
	kinds := make(map[componentvulns.Kind]string)
	for _, triplet := range cautils.MapComponentVulnResources(ksResourceMap) {
		if !allowed[triplet] {
			continue
		}
		_, _, resource := k8sinterface.StringToResourceGroup(triplet)
		if !filters.allows(resource) {
			continue
		}
		kinds[componentvulns.Kind(resource)] = triplet
	}
	return kinds
}

// collectComponentVulnerabilities builds the component vulnerability
// resources selected controls need. Components that cannot be assessed are
// recorded as partial pulls, and a kind with no resource at all is marked
// skipped, so its controls never read as plainly passed.
func (k8sHandler *K8sResourceHandler) collectComponentVulnerabilities(ctx context.Context, sessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo, allResources map[string]workloadinterface.IMetadata, ksResourceMap cautils.ExternalResources) {
	kinds := requiredComponentVulnKinds(sessionObj, scanInfo, ksResourceMap)
	if len(kinds) == 0 {
		return
	}
	triplets := make([]string, 0, len(kinds))
	for _, triplet := range kinds {
		triplets = append(triplets, triplet)
	}
	slices.Sort(triplets)

	// A single-workload scan never lists nodes or opens the vulnerability
	// DB; the selected kinds are skipped so their controls do not pass.
	if sessionObj.SingleResourceScan != nil {
		cautils.SetInfoMapForResources(singleResourceComponentVulnInfo, triplets, sessionObj.InfoMap)
		return
	}

	logger.L().Start("Matching cluster components against the vulnerability database...")
	inv, nodeGaps := k8sHandler.componentInventory(ctx, sessionObj.Report.ClusterAPIServerInfo, kinds)

	load := k8sHandler.componentVulnSources
	if load == nil {
		load = loadComponentVulnSources
	}
	sources, err := load(ctx, scanInfo)
	if err != nil {
		logger.L().StopError("Failed to load the vulnerability database")
		cautils.SetInfoMapForResources(err.Error(), triplets, sessionObj.InfoMap)
		return
	}
	if sources.close != nil {
		defer sources.close()
	}

	opts := componentvulns.Options{
		Index:       sources.index,
		IndexMaxAge: k8scveindex.DefaultMaxAge,
		DBBuilt:     sources.dbBuilt,
		Now:         time.Now(),
	}
	for kind := range kinds {
		opts.Kinds = append(opts.Kinds, kind)
	}
	res, err := componentvulns.Build(inv, sources.matcher, opts)
	if err != nil {
		logger.L().StopError("Failed to match cluster components")
		cautils.SetInfoMapForResources(err.Error(), triplets, sessionObj.InfoMap)
		return
	}
	res.Gaps = append(res.Gaps, nodeGaps...)

	built := make(map[string]bool, len(kinds))
	for _, r := range res.Resources {
		triplet := kinds[componentvulns.Kind(r.GetKind())]
		allResources[r.GetID()] = r
		ksResourceMap[triplet] = append(ksResourceMap[triplet], r.GetID())
		built[triplet] = true
	}

	partials := make([]cautils.PartialGVRPull, 0, len(res.Gaps))
	reasons := make(map[string]string)
	for _, g := range res.Gaps {
		triplet := kinds[g.Kind]
		partials = append(partials, cautils.PartialGVRPull{GVR: triplet, Selector: g.Selector, Error: g.Reason})
		if _, ok := reasons[triplet]; !ok {
			reasons[triplet] = g.Reason
		}
	}
	for _, triplet := range triplets {
		if built[triplet] {
			continue
		}
		reason := reasons[triplet]
		if reason == "" {
			reason = "no cluster component could be assessed"
		}
		cautils.SetInfoMapForResources(reason, []string{triplet}, sessionObj.InfoMap)
	}
	appendPartialPullsToSession(ctx, sessionObj, partials, "cluster component not fully assessed for vulnerabilities")
	logger.L().StopSuccess("Matched cluster components against the vulnerability database")
}

// componentInventory lists nodes only when a per-node kind is selected. A
// failed listing leaves the API-server inventory intact and reports a gap for
// each selected per-node kind, since Build sees no nodes to record gaps for.
func (k8sHandler *K8sResourceHandler) componentInventory(ctx context.Context, apiServer *version.Info, kinds map[componentvulns.Kind]string) (clustercomponents.Inventory, []componentvulns.Gap) {
	var perNode []componentvulns.Kind
	for _, kind := range []componentvulns.Kind{componentvulns.KubeletVulnerabilities, componentvulns.ContainerRuntimeVulnerabilities} {
		if _, ok := kinds[kind]; ok {
			perNode = append(perNode, kind)
		}
	}
	if len(perNode) == 0 {
		return clustercomponents.Build(apiServer, nil, nil), nil
	}

	nodes, err := k8sHandler.listNodes(ctx)
	if err != nil {
		gaps := make([]componentvulns.Gap, 0, len(perNode))
		for _, kind := range perNode {
			gaps = append(gaps, componentvulns.Gap{Kind: kind, Selector: componentvulns.ClusterSelector, Reason: err.Error()})
		}
		return clustercomponents.Build(apiServer, nil, nil), gaps
	}
	return clustercomponents.Build(apiServer, nodes, nil), nil
}

func (k8sHandler *K8sResourceHandler) listNodes(ctx context.Context) ([]v1.Node, error) {
	if k8sHandler.k8s == nil || k8sHandler.k8s.KubernetesClient == nil {
		return nil, fmt.Errorf("kubernetes client not available")
	}
	var nodes []v1.Node
	err := getter.ListWithPagination(ctx, func(opts metav1.ListOptions) (string, error) {
		chunk, err := k8sHandler.k8s.KubernetesClient.CoreV1().Nodes().List(ctx, opts)
		if err != nil {
			return "", err
		}
		nodes = append(nodes, chunk.Items...)
		return chunk.GetContinue(), nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}
	return nodes, nil
}
