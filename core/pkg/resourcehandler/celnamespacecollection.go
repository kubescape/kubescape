package resourcehandler

import (
	"context"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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
	needed map[string]struct{},
) (map[string]workloadinterface.IMetadata, error) {
	if len(needed) == 0 {
		return nil, nil
	}

	gvr := schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}
	clusterScoped := false
	fields := ""
	if len(needed) == 1 {
		for namespace := range needed {
			fields = getNamespacesSelector("Namespace", namespace, "=")
		}
	}
	// Visit pages as they arrive. The API may return every Namespace in the
	// allowed scope, but only those containing scan targets survive this visit.
	// This avoids retaining a cluster-wide slice and context map for a scan
	// narrowed to a small number of workloads.
	context := make(map[string]workloadinterface.IMetadata, len(needed))
	failures, sinkErr := k8sHandler.pullSingleResourceInto(ctx, &gvr, "", fields, selector, &clusterScoped, func(obj *unstructured.Unstructured) error {
		if _, ok := needed[obj.GetName()]; !ok {
			return nil
		}
		meta := workloadinterface.NewWorkloadObj(obj.Object)
		if meta != nil && meta.GetKind() == "Namespace" && meta.GetApiVersion() == "v1" {
			context[meta.GetID()] = meta
		}
		return nil
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if sinkErr != nil {
		return nil, sinkErr
	}
	for _, failure := range failures {
		logger.L().Ctx(ctx).Warning("could not collect Namespace context for CEL validation",
			helpers.String("selector", failure.selector), helpers.Error(failure.err))
	}
	return context, nil
}

// namespaceContextTargets records the namespaces that contain actual scan
// resources. Cluster-scoped objects have no namespaceObject binding.
func namespaceContextTargets(resources map[string]workloadinterface.IMetadata) map[string]struct{} {
	needed := make(map[string]struct{})
	for _, resource := range resources {
		if resource != nil && resource.GetNamespace() != "" {
			needed[resource.GetNamespace()] = struct{}{}
		}
	}
	return needed
}
