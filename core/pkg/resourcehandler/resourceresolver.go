package resourcehandler

import (
	"sort"
	"strings"
	"sync"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
)

type resolvedResource struct {
	groupVersionResourceTriplet string
	namespaced                  *bool
}

type resourceResolver func(group, version, resource string) []resolvedResource

func defaultResourceResolver(group, version, resource string) []resolvedResource {
	if version == "" || resource == "" {
		return nil
	}
	if _, err := k8sinterface.GetGroupVersionResource(resource); err != nil &&
		len(mapKSResourceToApiGroup(resource)) == 0 &&
		(group == "" || group == "*" || version == "*" || resource == "*") {
		// Without discovery, a wildcard cannot provide the missing group,
		// version, or declared CRD plural safely.
		return nil
	}
	resourceGroups := k8sinterface.ResourceGroupToSlice(group, version, resource)
	resolved := make([]resolvedResource, 0, len(resourceGroups))
	for _, resourceGroup := range resourceGroups {
		resolved = append(resolved, resolvedResource{groupVersionResourceTriplet: resourceGroup})
	}
	return resolved
}

type discoveredAPIResource struct {
	gvr        schema.GroupVersionResource
	kind       string
	namespaced bool
}

// newDiscoveryResourceResolver uses the API server's declared Kind, plural
// resource name, and namespace scope for live scans. If discovery is unavailable,
// built-in and Kubescape virtual resources retain the existing k8s-interface
// behavior; unknown CRDs are not guessed into live queries.
func newDiscoveryResourceResolver(client discovery.DiscoveryInterface) resourceResolver {
	var discovered []discoveredAPIResource
	if client != nil {
		_, resourceLists, err := client.ServerGroupsAndResources()
		if err != nil {
			logger.L().Warning("Kubernetes resource discovery was incomplete", helpers.Error(err))
		}
		discovered = collectDiscoveredResources(resourceLists)
	}

	warned := map[string]struct{}{}
	var warnedMu sync.Mutex

	return func(group, version, resource string) []resolvedResource {
		if version == "" || resource == "" {
			return nil
		}

		var resolved []resolvedResource
		for _, candidate := range discovered {
			if !matchesDiscoveryValue(group, candidate.gvr.Group) ||
				!matchesDiscoveryValue(version, candidate.gvr.Version) ||
				!matchesDiscoveryResource(resource, candidate) {
				continue
			}
			namespaced := candidate.namespaced
			resolved = append(resolved, resolvedResource{
				groupVersionResourceTriplet: k8sinterface.GroupVersionResourceToString(&candidate.gvr),
				namespaced:                  &namespaced,
			})
		}
		if len(resolved) > 0 {
			sort.Slice(resolved, func(i, j int) bool {
				return resolved[i].groupVersionResourceTriplet < resolved[j].groupVersionResourceTriplet
			})
			return resolved
		}

		if len(mapKSResourceToApiGroup(resource)) > 0 {
			return defaultResourceResolver(group, version, resource)
		}
		if _, err := k8sinterface.GetGroupVersionResource(resource); err == nil {
			return defaultResourceResolver(group, version, resource)
		}

		key := k8sinterface.JoinResourceTriplets(group, version, resource)
		warnedMu.Lock()
		if _, ok := warned[key]; !ok {
			logger.L().Warning("resource was not found in Kubernetes discovery; skipping live query",
				helpers.String("apiGroup", group),
				helpers.String("apiVersion", version),
				helpers.String("resource", resource))
			warned[key] = struct{}{}
		}
		warnedMu.Unlock()
		return nil
	}
}

func collectDiscoveredResources(resourceLists []*metav1.APIResourceList) []discoveredAPIResource {
	var discovered []discoveredAPIResource
	for _, resourceList := range resourceLists {
		if resourceList == nil {
			continue
		}
		groupVersion, err := schema.ParseGroupVersion(resourceList.GroupVersion)
		if err != nil {
			continue
		}
		for _, apiResource := range resourceList.APIResources {
			if apiResource.Kind == "" || apiResource.Name == "" || strings.Contains(apiResource.Name, "/") {
				continue
			}
			discovered = append(discovered, discoveredAPIResource{
				gvr:        groupVersion.WithResource(apiResource.Name),
				kind:       apiResource.Kind,
				namespaced: apiResource.Namespaced,
			})
		}
	}
	return discovered
}

func matchesDiscoveryValue(policyValue, discoveredValue string) bool {
	return policyValue == "*" || policyValue == discoveredValue
}

func matchesDiscoveryResource(policyResource string, discovered discoveredAPIResource) bool {
	return policyResource == "*" ||
		strings.EqualFold(policyResource, discovered.kind) ||
		strings.EqualFold(policyResource, discovered.gvr.Resource)
}
