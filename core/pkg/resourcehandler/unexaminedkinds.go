package resourcehandler

import (
	"sort"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
)

// examinedResourceKey is one side of the unexamined-kinds diff. The query set is
// keyed by formatted triplets and discovery hands back a GroupVersionResource,
// so both are parsed into this before being compared, rather than one side
// being re-formatted into the other's spelling.
type examinedResourceKey struct {
	group    string
	version  string
	resource string
}

// queriedResourceKeys parses the query set's triplet keys. A key that is
// not a triplet cannot name a discovered resource, so it is dropped rather than
// kept as a partly-empty identity that could match one.
func queriedResourceKeys(queryable QueryableResources) map[examinedResourceKey]struct{} {
	queried := make(map[examinedResourceKey]struct{}, len(queryable))
	for triplet := range queryable {
		group, version, resource := k8sinterface.StringToResourceGroup(triplet)
		if resource == "" {
			continue
		}
		queried[examinedResourceKey{group: group, version: version, resource: resource}] = struct{}{}
	}
	return queried
}

// computeUnexaminedKinds returns the listable resource kinds discovery
// reported that queryable does not include, sorted by GVR triplet. discovered
// only ever contains real API-server-served kinds (see collectDiscoveredResources),
// so Kubescape's own virtual/external resources (host sensor, cloud, RBAC)
// never appear here and need no filtering.
func computeUnexaminedKinds(discovered []discoveredAPIResource, queryable QueryableResources) []cautils.UnexaminedKind {
	queried := queriedResourceKeys(queryable)

	var unexamined []cautils.UnexaminedKind
	for _, candidate := range discovered {
		if !candidate.listable {
			continue
		}
		identity := examinedResourceKey{
			group:    candidate.gvr.Group,
			version:  candidate.gvr.Version,
			resource: candidate.gvr.Resource,
		}
		if _, examined := queried[identity]; examined {
			continue
		}
		unexamined = append(unexamined, cautils.UnexaminedKind{
			GroupVersionResource: k8sinterface.GroupVersionResourceToString(&candidate.gvr),
			Kind:                 candidate.kind,
		})
	}
	sort.Slice(unexamined, func(i, j int) bool {
		return unexamined[i].GroupVersionResource < unexamined[j].GroupVersionResource
	})
	return unexamined
}
