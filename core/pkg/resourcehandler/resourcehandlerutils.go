package resourcehandler

import (
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// utils which are common to all resource handlers
func addSingleResourceToResourceMaps(k8sResources cautils.K8SResources, allResources map[string]workloadinterface.IMetadata, wl workloadinterface.IWorkload, resolver resourceResolver) {
	if wl == nil {
		return
	}
	// if k8sinterface.WorkloadHasParent(wl) {
	// 	return
	// }

	resolved := resolver(wl.GetGroup(), wl.GetVersion(), wl.GetKind())
	if len(resolved) != 1 {
		logger.L().Warning("unable to resolve object resource", helpers.String("kind", wl.GetKind()), helpers.String("id", wl.GetID()))
		return
	}

	resourceGroups := append([]string{resolved[0].groupVersionResourceTriplet}, resolved[0].comparisonTriplets...)
	seen := make(map[string]struct{}, len(resourceGroups))
	for _, resourceGroup := range resourceGroups {
		if _, exists := seen[resourceGroup]; exists {
			continue
		}
		seen[resourceGroup] = struct{}{}
		k8sResources[resourceGroup] = append(k8sResources[resourceGroup], wl.GetID())
	}
	allResources[wl.GetID()] = wl
}

func getQueryableResourceMapFromPolicies(frameworks []reporthandling.Framework, resource workloadinterface.IWorkload, scanningScope reporthandling.ScanningScopeType, resolver resourceResolver) (QueryableResources, map[string]bool) {
	queryableResources := make(QueryableResources)
	excludedRulesMap := make(map[string]bool)
	namespace := getScannedResourceNamespace(resource, resolver)

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
					updateQueryableResourcesMapFromRuleMatchObject(&rule.Match[i], resourcesFilterMap, queryableResources, namespace, resolver)
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
func getScannedResourceNamespace(workload workloadinterface.IWorkload, resolver resourceResolver) string {
	if workload == nil {
		return ""
	}
	if workload.GetKind() == "Namespace" {
		return workload.GetName()
	}

	resolved := resolver(workload.GetGroup(), workload.GetVersion(), workload.GetKind())
	if len(resolved) == 1 && resolved[0].namespaced != nil {
		if *resolved[0].namespaced {
			return workload.GetNamespace()
		}
		return ""
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

	resourceAliases := make(map[string]struct{})
	for _, alias := range offlineManifestResourceAliases(resourceKind) {
		resourceAliases[alias] = struct{}{}
	}
	matchesInputResource := func(resource string) bool {
		_, exists := resourceAliases[strings.ToLower(resource)]
		return exists
	}

	ruleApplies := false
	for resource := range resourceMap {
		if matchesInputResource(resource) {
			ruleApplies = true
			break
		}
	}
	if !ruleApplies {
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
		if matchesInputResource(r) {
			continue
		}

		_, isCurrentResourceWorkload := workloadKinds[r]
		resourceMap[r] = !isCurrentResourceWorkload || !isInputResourceWorkload
	}

	return resourceMap
}

// updateQueryableResourcesMapFromRuleMatchObject updates the queryableResources map with the relevant resources from the match object.
// if namespace is not empty, the namespace filter is added to the queryable resources (which are namespaced)
// if resourcesFilterMap is not nil, only the resources with value 'true' will be added to the queryable resources
func updateQueryableResourcesMapFromRuleMatchObject(match *reporthandling.RuleMatchObjects, resourcesFilterMap map[string]bool, queryableResources QueryableResources, namespace string, resolver resourceResolver) {
	for _, apiGroup := range match.APIGroups {
		for _, apiVersions := range match.APIVersions {
			var handledResources []string
			for _, resource := range match.Resources {
				if sharesOfflineResourceAlias(resource, handledResources) {
					continue
				}
				handledResources = append(handledResources, resource)
				if resourcesFilterMap != nil {
					if relevant := resourcesFilterMap[resource]; !relevant {
						continue
					}
				}

				for _, resolved := range resolver(apiGroup, apiVersions, resource) {
					resolvedGroup, resolvedVersion, resourceName := k8sinterface.StringToResourceGroup(resolved.groupVersionResourceTriplet)
					gvr := &schema.GroupVersionResource{Group: resolvedGroup, Version: resolvedVersion, Resource: resourceName}
					globalFieldSelector := getNamespacesSelector(resource, namespace, "=")
					if resolved.namespaced != nil {
						globalFieldSelector = getNamespacesSelectorForScope(gvr, namespace, "=", *resolved.namespaced)
					}
					queryableResource := QueryableResource{
						GroupVersionResourceTriplet: resolved.groupVersionResourceTriplet,
						Namespaced:                  resolved.namespaced,
					}
					queryableResource.AddFieldSelector(globalFieldSelector)

					if len(match.FieldSelector) == 0 {
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

func sharesOfflineResourceAlias(resource string, handledResources []string) bool {
	resource = strings.ToLower(resource)
	for _, handled := range handledResources {
		handled = strings.ToLower(handled)
		if resource == handled || containsString(offlineManifestResourceAliases(resource), handled) ||
			containsString(offlineManifestResourceAliases(handled), resource) {
			return true
		}
	}
	return false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
