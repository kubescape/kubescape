package resourcehandler

import (
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
)

// utils which are common to all resource handlers
func addWorkloadToResourceMaps(k8sResources cautils.K8SResources, allResources map[string]workloadinterface.IMetadata, wl workloadinterface.IWorkload) {
	if wl == nil {
		return
	}

	allResources[wl.GetID()] = wl

	resourceGroup := k8sinterface.ResourceGroupToSlice(wl.GetGroup(), wl.GetVersion(), wl.GetKind())[0]
	k8sResources[resourceGroup] = append(k8sResources[resourceGroup], wl.GetID())
}

func getQueryableResourceMapFromPolicies(handler IResourceHandler, frameworks []reporthandling.Framework, workload workloadinterface.IWorkload) (QueryableResources, map[string]bool) {
	queryableResources := make(QueryableResources)
	excludedRulesMap := make(map[string]bool)

	parentKind := handler.GetWorkloadParentKind(workload)
	namespace := getScannedWorkloadNamespace(workload)

	for _, framework := range frameworks {
		for _, control := range framework.Controls {
			for _, rule := range control.Rules {
				var resourcesFilterMap map[string]bool = nil
				// for workload scan, we need to filter the resources according to the given workload and its owner reference
				if workload != nil {
					if resourcesFilterMap = filterRuleMatchesForWorkload(workload.GetKind(), parentKind, rule.Match); resourcesFilterMap == nil {
						// rule does not apply to this workload
						excludedRulesMap[rule.Name] = false
						continue
					}
				}
				for _, match := range rule.Match {
					updateQueryableResourcesMapFromRuleMatchObject(&match, resourcesFilterMap, queryableResources, namespace)
				}
			}
		}
	}

	return queryableResources, excludedRulesMap
}

// getScannedWorkloadNamespace returns the namespace of the scanned workload.
// If workload is nil (e.g. cluster scan), returns an empty string
// If the workload is a namespaced or the Namespace iself, returns the namespace name
// In all other cases, returns an empty string
func getScannedWorkloadNamespace(workload workloadinterface.IWorkload) string {
	if workload == nil {
		return ""
	}
	if workload.GetKind() == "Namespace" {
		return workload.GetName()
	}

	if k8sinterface.IsResourceInNamespaceScope(workload.GetKind()) {
		return workload.GetNamespace()
	}

	return ""
}

// filterRuleMatches returns a map, of which resources should be queried for a given workload and its owner reference
// The map is of the form: map[<resource>]bool (The bool value indicates whether the resource should be queried or not)
// The function will return a nil map if the rule does not apply to the given workload
func filterRuleMatchesForWorkload(workloadKind, ownerReferenceKind string, matchObjects []reporthandling.RuleMatchObjects) map[string]bool {
	resourceMap := make(map[string]bool)
	for _, match := range matchObjects {
		for _, resource := range match.Resources {
			resourceMap[resource] = false
		}
	}

	// rule does not apply to this workload
	if _, exists := resourceMap[workloadKind]; !exists {
		return nil
	}

	workloadKinds := map[string]bool{
		"Pod":         false,
		"DaemonSet":   false,
		"Deployment":  false,
		"ReplicaSet":  false,
		"StatefulSet": false,
		"CronJob":     false,
		"Job":         false,
	}

	_, isInputResourceWorkload := workloadKinds[workloadKind]

	//  has owner reference
	if isInputResourceWorkload && ownerReferenceKind != "" {
		// owner reference kind exists in the matches - that means the rule does not apply to the given workload
		if _, exist := resourceMap[ownerReferenceKind]; exist {
			return nil
		}
	}

	for r := range resourceMap {
		// we don't need to query the same resource
		if r == workloadKind {
			continue
		}

		_, isCurrentResourceWorkload := workloadKinds[r]
		resourceMap[r] = !isCurrentResourceWorkload || !isInputResourceWorkload
	}

	return resourceMap
}

// getOwnerReferenceKind returns the kind of the first owner reference of the given object
// If the object has no owner references or not a valid workload, returns an empty string
func getOwnerReferenceKind(object workloadinterface.IMetadata) string {
	if !k8sinterface.IsTypeWorkload(object.GetObject()) {
		return ""
	}
	wl := workloadinterface.NewWorkloadObj(object.GetObject())
	ownerReferences, err := wl.GetOwnerReferences()
	if err != nil || len(ownerReferences) == 0 {
		return ""
	}
	return ownerReferences[0].Kind
}

// updateQueryableResourcesMapFromMatch updates the queryableResources map with the relevant resources from the match object.
// if namespace is not empty, the namespace filter is added to the queryable resources (which are namespaced)
// if resourcesFilterMap is not nil, only the resources with value 'true' will be added to the queryable resources
func updateQueryableResourcesMapFromRuleMatchObject(match *reporthandling.RuleMatchObjects, resourcesFilterMap map[string]bool, queryableResources QueryableResources, namespace string) {
	for _, apiGroup := range match.APIGroups {
		for _, apiVersions := range match.APIVersions {
			for _, resource := range match.Resources {
				if resourcesFilterMap != nil {
					if relevant := resourcesFilterMap[resource]; !relevant {
						continue
					}
				}

				groupResources := k8sinterface.ResourceGroupToString(apiGroup, apiVersions, resource)
				// if namespace filter is set, we are scanning a workload in a specific namespace
				// calling the getNamespacesSelector will add the namespace field selector (or name for Namespace resource)
				globalFieldSelector := getNamespacesSelector(resource, namespace, "=")

				for _, groupResource := range groupResources {
					queryableResource := QueryableResource{
						GroupVersionResourceTriplet: groupResource,
					}
					queryableResource.AddFieldSelector(globalFieldSelector)

					if match.FieldSelector == nil || len(match.FieldSelector) == 0 {
						queryableResources.Add(queryableResource)
						continue
					}

					for _, fieldSelector := range match.FieldSelector {
						qrCopy := queryableResource.Copy()
						qrCopy.AddFieldSelector(fieldSelector)
						queryableResources.Add(qrCopy)
					}

				}
			}
		}
	}
}
