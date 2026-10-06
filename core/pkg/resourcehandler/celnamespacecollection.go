package resourcehandler

import (
	"context"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// needsSupplementalCELNamespaces detects when normal CEL Namespace queries
// cannot provide the input that namespaceObject needs. A workload label
// selector commonly matches Pods but not their Namespace, and a kind filter
// may intentionally exclude Namespace as a scan target. In either case the
// Namespace is still needed as evaluation context.
func needsSupplementalCELNamespaces(scanInfo *cautils.ScanInfo, policies []reporthandling.Framework) bool {
	if scanInfo == nil || (scanInfo.LabelSelector == "" && newKindFilters(scanInfo).allows("Namespace")) {
		return false
	}
	for _, framework := range policies {
		for _, control := range framework.Controls {
			for _, rule := range control.Rules {
				if rule.RuleLanguage == reporthandling.CELLanguage {
					return true
				}
			}
		}
	}
	return false
}

// collectSupplementalCELNamespaces retrieves Namespace objects only as CEL
// input. The caller keeps them separate from the scan's resource catalog and
// target indexes, so they cannot affect reporting or empty-scan detection.
func (k8sHandler *K8sResourceHandler) collectSupplementalCELNamespaces(
	ctx context.Context,
	selector IFieldSelector,
	singleScan workloadinterface.IWorkload,
	resolver resourceResolver,
) (map[string]workloadinterface.IMetadata, error) {
	var namespace string
	if singleScan != nil {
		if singleScan.GetKind() == "Namespace" {
			return nil, nil
		}
		namespace = getScannedResourceNamespace(singleScan, resolver)
	}
	if singleScan != nil && namespace == "" {
		return nil, nil
	}

	fields := ""
	if singleScan != nil {
		fields = getNamespacesSelector("Namespace", namespace, "=")
	}
	gvr := schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}
	clusterScoped := false
	objects, failures := k8sHandler.pullSingleResource(ctx, &gvr, "", fields, selector, &clusterScoped)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, failure := range failures {
		logger.L().Ctx(ctx).Warning("could not collect Namespace context for CEL validation",
			helpers.String("selector", failure.selector), helpers.Error(failure.err))
	}
	context := make(map[string]workloadinterface.IMetadata, len(objects))
	for i := range objects {
		meta := workloadinterface.NewWorkloadObj(objects[i].Object)
		if meta.GetKind() == "Namespace" && meta.GetApiVersion() == "v1" && meta.GetName() != "" {
			context[meta.GetID()] = meta
		}
	}
	return context, nil
}
