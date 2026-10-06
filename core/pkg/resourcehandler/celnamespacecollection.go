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
// input. They enter AllResources so the processor can resolve namespaceObject,
// but not K8SResources, so a label or kind filter does not start scanning
// Namespace objects as additional policy targets. This works for both eager
// and streaming collection after their normal kind filters have run.
func (k8sHandler *K8sResourceHandler) collectSupplementalCELNamespaces(
	ctx context.Context,
	selector IFieldSelector,
	singleScan workloadinterface.IWorkload,
	resolver resourceResolver,
	allResources map[string]workloadinterface.IMetadata,
) error {
	var namespace string
	if singleScan != nil {
		if singleScan.GetKind() == "Namespace" {
			return nil
		}
		namespace = getScannedResourceNamespace(singleScan, resolver)
	}
	if singleScan != nil && namespace == "" {
		return nil
	}

	fields := ""
	if singleScan != nil {
		fields = getNamespacesSelector("Namespace", namespace, "=")
	}
	gvr := schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}
	clusterScoped := false
	objects, failures := k8sHandler.pullSingleResource(ctx, &gvr, "", fields, selector, &clusterScoped)
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, failure := range failures {
		logger.L().Ctx(ctx).Warning("could not collect Namespace context for CEL validation",
			helpers.String("selector", failure.selector), helpers.Error(failure.err))
	}
	for i := range objects {
		meta := workloadinterface.NewWorkloadObj(objects[i].Object)
		if meta.GetKind() == "Namespace" && meta.GetApiVersion() == "v1" && meta.GetName() != "" {
			allResources[meta.GetID()] = meta
		}
	}
	return nil
}
