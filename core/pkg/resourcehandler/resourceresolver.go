package resourcehandler

import (
	"errors"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
)

type resolvedResource struct {
	groupVersionResourceTriplet string
	comparisonTriplets          []string
	namespaced                  *bool
	// kind is the Kind the resource is served as, empty when the resolver had no
	// authoritative source for it — only discovery and a file scan's manifests
	// know it, and a guess would be worse than reporting it unknown.
	kind string
}

type resourceResolver func(group, version, resource string) []resolvedResource

// coreAPIGroupAlias is how a policy rule may spell the core API group. Every
// other identity in a scan carries it as the empty string, so the two have to
// be reconciled before a rule is compared against anything.
const coreAPIGroupAlias = "core"

// normalizeAPIGroup resolves a rule's API group to the spelling discovery, the
// resource triplets and the API server all use.
func normalizeAPIGroup(group string) string {
	if group == coreAPIGroupAlias {
		return ""
	}
	return group
}

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
			if !matchesOfflineManifestValue(normalizeAPIGroup(group), manifestResource.group) ||
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
				kind:                        manifestResource.kind,
			})
		}
		return resolved
	}
}

func matchesOfflineManifestValue(policyValue, manifestValue string) bool {
	return policyValue == "*" || policyValue == manifestValue
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
	listable   bool
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

	logged := map[string]struct{}{}
	var loggedMu sync.Mutex
	logOnce := func(key string, emit func()) {
		loggedMu.Lock()
		defer loggedMu.Unlock()
		if _, ok := logged[key]; ok {
			return
		}
		logged[key] = struct{}{}
		emit()
	}

	return func(group, version, resource string) []resolvedResource {
		if version == "" || resource == "" {
			return nil
		}

		var resolved []resolvedResource
		var skippedUnlistable []string
		for _, candidate := range discovered {
			if !matchesDiscoveryValue(group, candidate.gvr.Group) ||
				!matchesDiscoveryValue(version, candidate.gvr.Version) ||
				!matchesDiscoveryResource(resource, candidate) {
				continue
			}
			if !candidate.listable {
				// Collection is a cluster-wide LIST, so a resource the API
				// server does not serve "list" for can only fail. Skipping it
				// keeps create-only endpoints such as tokenreviews out of
				// wildcard fan-out.
				skippedUnlistable = append(skippedUnlistable, k8sinterface.GroupVersionResourceToString(&candidate.gvr))
				continue
			}
			namespaced := candidate.namespaced
			resolved = append(resolved, resolvedResource{
				groupVersionResourceTriplet: k8sinterface.GroupVersionResourceToString(&candidate.gvr),
				namespaced:                  &namespaced,
				kind:                        candidate.kind,
			})
		}
		if len(resolved) > 0 {
			sort.Slice(resolved, func(i, j int) bool {
				return resolved[i].groupVersionResourceTriplet < resolved[j].groupVersionResourceTriplet
			})
			return resolved
		}

		if len(skippedUnlistable) > 0 {
			// Discovery answered for this resource, so the built-in fallbacks
			// below must not resurrect the GVR it declared unlistable.
			sort.Strings(skippedUnlistable)
			logOnce("unlistable:"+k8sinterface.JoinResourceTriplets(group, version, resource), func() {
				details := []helpers.IDetails{
					helpers.String("apiGroup", group),
					helpers.String("apiVersion", version),
					helpers.String("resource", resource),
					helpers.String("skipped", strings.Join(skippedUnlistable, ",")),
				}
				// A policy that names the resource outright loses its only
				// input, which is worth a warning. A wildcard match sweeping
				// past create-only endpoints is expected, so keep it quiet.
				if isExplicitPolicyMatch(group, version, resource) {
					logger.L().Warning("resource does not support list in Kubernetes discovery; skipping live query", details...)
					return
				}
				logger.L().Debug("resource does not support list in Kubernetes discovery; skipping live query", details...)
			})
			return nil
		}

		if len(mapKSResourceToApiGroup(resource)) > 0 {
			return defaultResourceResolver(group, version, resource)
		}
		if _, err := k8sinterface.GetGroupVersionResource(resource); err == nil {
			return defaultResourceResolver(group, version, resource)
		}

		logOnce("undiscovered:"+k8sinterface.JoinResourceTriplets(group, version, resource), func() {
			logger.L().Warning("resource was not found in Kubernetes discovery; skipping live query",
				helpers.String("apiGroup", group),
				helpers.String("apiVersion", version),
				helpers.String("resource", resource))
		})
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

// recordDiscoveryFailureDependencies links unresolved policy dependencies to the
// discovery failure that prevented them from being resolved. Discovery errors
// remain partial pulls because they describe the discovery stage. The synthetic
// dependency key lets scan coverage determine whether a control had any other
// successfully resolved input.
func recordDiscoveryFailureDependencies(
	frameworks []reporthandling.Framework,
	scannedResource workloadinterface.IWorkload,
	scanningScope reporthandling.ScanningScopeType,
	resolver resourceResolver,
	discoveryFailures []cautils.PartialGVRPull,
	resourceToControls map[string][]string,
	warned map[string]struct{},
) {
	if len(discoveryFailures) == 0 || len(frameworks) == 0 {
		return
	}

	for _, framework := range frameworks {
		for _, control := range framework.Controls {
			for _, rule := range control.Rules {
				if cautils.ShouldSkipRuleWithWarned(control, rule, scanningScope, warned) {
					continue
				}

				var resourcesFilterMap map[string]bool
				if scannedResource != nil {
					resourcesFilterMap = filterRuleMatchesForResource(scannedResource.GetKind(), rule.Match)
					if resourcesFilterMap == nil {
						continue
					}
				}

				for _, match := range rule.Match {
					for _, group := range match.APIGroups {
						for _, version := range match.APIVersions {
							for _, resource := range match.Resources {
								if resourcesFilterMap != nil && !resourcesFilterMap[resource] {
									continue
								}
								resolved := resolver(group, version, resource)

								for _, failure := range discoveryFailures {
									failedGroupVersion, matches := matchingDiscoveryFailureGroupVersion(failure, group, version)
									if !matches || resolvesGroupVersion(resolved, failedGroupVersion) {
										continue
									}
									if !slices.Contains(resourceToControls[failure.GVR], control.ControlID) {
										resourceToControls[failure.GVR] = append(resourceToControls[failure.GVR], control.ControlID)
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

func matchingDiscoveryFailureGroupVersion(failure cautils.PartialGVRPull, group, version string) (schema.GroupVersion, bool) {
	if failure.Selector != "discovery" || !strings.HasPrefix(failure.GVR, "discovery:") {
		return schema.GroupVersion{}, false
	}
	failedGroupVersion := strings.TrimPrefix(failure.GVR, "discovery:")
	if failedGroupVersion == "*" {
		return schema.GroupVersion{}, false
	}

	groupVersion, err := schema.ParseGroupVersion(failedGroupVersion)
	if err != nil {
		return schema.GroupVersion{}, false
	}
	groupMatches := group == "*" || normalizeAPIGroup(group) == groupVersion.Group
	versionMatches := version == "*" || version == groupVersion.Version
	return groupVersion, groupMatches && versionMatches
}

func resolvesGroupVersion(resolved []resolvedResource, groupVersion schema.GroupVersion) bool {
	for _, candidate := range resolved {
		group, version, _ := k8sinterface.StringToResourceGroup(candidate.groupVersionResourceTriplet)
		if normalizeAPIGroup(group) == groupVersion.Group && version == groupVersion.Version {
			return true
		}
	}
	return false
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
				listable:   discoveryDeclaresList(apiResource),
			})
		}
	}
	return discovered
}

// isExplicitPolicyMatch reports whether a rule match names a single resource
// identity rather than relying on wildcard expansion.
func isExplicitPolicyMatch(group, version, resource string) bool {
	return group != "*" && version != "*" && resource != "*"
}

// discoveryDeclaresList reports whether the API server advertises "list" for a
// resource. An empty verb set means discovery did not report the verbs, so the
// resource stays eligible rather than being dropped on missing data.
func discoveryDeclaresList(apiResource metav1.APIResource) bool {
	if len(apiResource.Verbs) == 0 {
		return true
	}
	return slices.Contains([]string(apiResource.Verbs), "list")
}

func matchesDiscoveryValue(policyValue, discoveredValue string) bool {
	return policyValue == "*" || policyValue == discoveredValue
}

func matchesDiscoveryResource(policyResource string, discovered discoveredAPIResource) bool {
	return policyResource == "*" ||
		strings.EqualFold(policyResource, discovered.kind) ||
		strings.EqualFold(policyResource, discovered.gvr.Resource)
}
