package resourcehandler

import (
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
)

// utils which are common to all resource handlers
func addSingleResourceToResourceMaps(k8sResources cautils.K8SResources, allResources map[string]workloadinterface.IMetadata, wl workloadinterface.IWorkload) {
	if wl == nil {
		return
	}
	// if k8sinterface.WorkloadHasParent(wl) {
	// 	return
	// }

	allResources[wl.GetID()] = wl

	resourceGroup := k8sinterface.ResourceGroupToSlice(wl.GetGroup(), wl.GetVersion(), wl.GetKind())[0]
	k8sResources[resourceGroup] = append(k8sResources[resourceGroup], wl.GetID())
}

func getQueryableResourceMapFromPolicies(frameworks []reporthandling.Framework, resource workloadinterface.IWorkload, scanningScope reporthandling.ScanningScopeType) (QueryableResources, map[string]bool) {
	queryableResources := make(QueryableResources)
	excludedRulesMap := make(map[string]bool)
	namespace := getScannedResourceNamespace(resource)

	for _, framework := range frameworks {
		for _, control := range framework.Controls {
			for _, rule := range control.Rules {
				// check if the rule should be skipped according to the scanning scope and the rule attributes
				if cautils.ShouldSkipRule(control, rule, scanningScope) {
					continue
				}

				var resourcesFilterMap map[string]bool = nil
				// for single resource scan, we need to filter the rules and which resources to query according to the given resource
				if resource != nil {
					if resourcesFilterMap = filterRuleMatchesForResource(resource.GetKind(), rule.Match); resourcesFilterMap == nil {
						// rule does not apply to this resource
						excludedRulesMap[rule.Name] = false
						continue
					}
				}
				for i := range rule.Match {
					updateQueryableResourcesMapFromRuleMatchObject(&rule.Match[i], resourcesFilterMap, queryableResources, namespace)
				}
			}
		}
	}

	return queryableResources, excludedRulesMap
}

// getScannedResourceNamespace returns the namespace of the scanned resource.
// If input is nil (e.g. cluster scan), returns an empty string
// If the resource is a namespaced or the Namespace itself, returns the namespace name
// In all other cases, returns an empty string
func getScannedResourceNamespace(workload workloadinterface.IWorkload) string {
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

// filterRuleMatchesForResource returns a map, of which resources should be queried for a given resource
// The map is of the form: map[<resource>]bool (The bool value indicates whether the resource should be queried or not)
// The function will return a nil map if the rule does not apply to the given workload
func filterRuleMatchesForResource(resourceKind string, matchObjects []reporthandling.RuleMatchObjects) map[string]bool {
	resourceMap := make(map[string]bool)
	for _, match := range matchObjects {
		for _, resource := range match.Resources {
			resourceMap[resource] = false
		}
	}

	// rule does not apply to this workload
	if _, exists := resourceMap[resourceKind]; !exists {
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

	_, isInputResourceWorkload := workloadKinds[resourceKind]

	for r := range resourceMap {
		// we don't need to query the same resource
		if r == resourceKind {
			continue
		}

		_, isCurrentResourceWorkload := workloadKinds[r]
		resourceMap[r] = !isCurrentResourceWorkload || !isInputResourceWorkload
	}

	return resourceMap
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
