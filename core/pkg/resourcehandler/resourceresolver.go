package resourcehandler

import (
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
)

type resolvedResource struct {
	groupVersionResourceTriplet string
	comparisonTriplets          []string
	namespaced                  *bool
}

type resourceResolver func(group, version, resource string) []resolvedResource

type offlineManifestResource struct {
	group      string
	version    string
	kind       string
	namespaced bool
}

// newOfflineManifestResourceResolver builds the only discovery information a
// file scan can trust: the identities declared by the manifests being scanned.
// It deliberately does not consult the k8s-interface discovery snapshot.
func newOfflineManifestResourceResolver(mappedResources map[string][]workloadinterface.IMetadata) resourceResolver {
	resourcesByGVK := make(map[string]offlineManifestResource)
	seenWorkloads := make(map[string]struct{})
	for _, workloads := range mappedResources {
		for _, workload := range workloads {
			if workload == nil {
				continue
			}
			if _, seen := seenWorkloads[workload.GetID()]; seen {
				continue
			}
			seenWorkloads[workload.GetID()] = struct{}{}

			group, version := k8sinterface.SplitApiVersion(workload.GetApiVersion())
			kind := workload.GetKind()
			if version == "" || kind == "" {
				continue
			}

			key := k8sinterface.JoinResourceTriplets(group, version, strings.ToLower(kind))
			entry := resourcesByGVK[key]
			entry.group = group
			entry.version = version
			entry.kind = kind
			entry.namespaced = entry.namespaced ||
				workload.GetNamespace() != "" ||
				k8sinterface.IsResourceInNamespaceScope(kind)
			resourcesByGVK[key] = entry
		}
	}

	resources := make([]offlineManifestResource, 0, len(resourcesByGVK))
	for _, resource := range resourcesByGVK {
		resources = append(resources, resource)
	}
	sort.Slice(resources, func(i, j int) bool {
		left := k8sinterface.JoinResourceTriplets(resources[i].group, resources[i].version, resources[i].kind)
		right := k8sinterface.JoinResourceTriplets(resources[j].group, resources[j].version, resources[j].kind)
		return left < right
	})

	return func(group, version, resource string) []resolvedResource {
		if version == "" || resource == "" {
			return nil
		}

		var resolved []resolvedResource
		for _, manifestResource := range resources {
			if !matchesOfflineManifestValue(group, manifestResource.group) ||
				!matchesOfflineManifestValue(version, manifestResource.version) ||
				!matchesOfflineManifestResource(resource, manifestResource.kind) {
				continue
			}

			aliases := offlineManifestResourceTriplets(manifestResource.group, manifestResource.version, manifestResource.kind)
			primary := aliases[0]
			if resource != "*" && !strings.EqualFold(resource, manifestResource.kind) {
				requested := k8sinterface.JoinResourceTriplets(manifestResource.group, manifestResource.version, strings.ToLower(resource))
				for _, alias := range aliases {
					if alias == requested {
						primary = alias
						break
					}
				}
			}

			comparisons := make([]string, 0, len(aliases)-1)
			for _, alias := range aliases {
				if alias != primary {
					comparisons = append(comparisons, alias)
				}
			}
			namespaced := manifestResource.namespaced
			resolved = append(resolved, resolvedResource{
				groupVersionResourceTriplet: primary,
				comparisonTriplets:          comparisons,
				namespaced:                  &namespaced,
			})
		}
		return resolved
	}
}

func matchesOfflineManifestValue(policyValue, manifestValue string) bool {
	if policyValue == "*" || policyValue == manifestValue {
		return true
	}
	return policyValue == "core" && manifestValue == ""
}

func matchesOfflineManifestResource(policyResource, manifestKind string) bool {
	if policyResource == "*" || strings.EqualFold(policyResource, manifestKind) {
		return true
	}
	policyResource = strings.ToLower(policyResource)
	for _, alias := range offlineManifestResourceAliases(manifestKind) {
		if policyResource == alias {
			return true
		}
	}
	return false
}

func defaultResourceResolver(group, version, resource string) []resolvedResource {
	if version == "" || resource == "" {
		return nil
	}
	_, builtInErr := k8sinterface.GetGroupVersionResource(resource)
	isUnknown := builtInErr != nil && len(mapKSResourceToApiGroup(resource)) == 0
	if isUnknown && (group == "" || group == "*" || version == "*" || resource == "*") {
		// Without discovery, a wildcard cannot provide the missing group,
		// version, or declared CRD plural safely.
		return nil
	}
	if isUnknown {
		// Offline custom-resource identities are comparison keys, not REST
		// queries. Normalize case while preserving the policy-provided singular
		// or plural form; file indexing supplies both manifest-derived aliases.
		return []resolvedResource{{
			groupVersionResourceTriplet: k8sinterface.JoinResourceTriplets(group, version, strings.ToLower(resource)),
			comparisonTriplets:          offlineManifestResourceTriplets(group, version, resource),
		}}
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
func newDiscoveryResourceResolver(client discovery.DiscoveryInterface) (resourceResolver, []cautils.PartialGVRPull) {
	var discovered []discoveredAPIResource
	var discoveryFailures []cautils.PartialGVRPull
	if client != nil {
		_, resourceLists, err := client.ServerGroupsAndResources()
		if err != nil {
			logger.L().Warning("Kubernetes resource discovery was incomplete", helpers.Error(err))
			discoveryFailures = getDiscoveryFailures(err)
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
	}, discoveryFailures
}

func getDiscoveryFailures(err error) []cautils.PartialGVRPull {
	var groupFailure *discovery.ErrGroupDiscoveryFailed
	if !errors.As(err, &groupFailure) {
		return []cautils.PartialGVRPull{{
			GVR:      "discovery:*",
			Selector: "discovery",
			Error:    err.Error(),
		}}
	}

	groupVersions := make([]schema.GroupVersion, 0, len(groupFailure.Groups))
	for groupVersion := range groupFailure.Groups {
		groupVersions = append(groupVersions, groupVersion)
	}
	sort.Slice(groupVersions, func(i, j int) bool {
		return groupVersions[i].String() < groupVersions[j].String()
	})

	failures := make([]cautils.PartialGVRPull, 0, len(groupVersions))
	for _, groupVersion := range groupVersions {
		failures = append(failures, cautils.PartialGVRPull{
			GVR:      "discovery:" + groupVersion.String(),
			Selector: "discovery",
			Error:    groupFailure.Groups[groupVersion].Error(),
		})
	}
	return failures
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
