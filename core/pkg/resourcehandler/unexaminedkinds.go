package resourcehandler

import (
	"sort"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"k8s.io/apimachinery/pkg/version"
)

// examinedResourceKey is one side of the unexamined-kinds diff. The query set is
// keyed by formatted triplets and discovery hands back a GroupVersionResource,
// so both are parsed into this before being compared, rather than one side
// being re-formatted into the other's spelling.
//
// The served version is deliberately not part of it. Every version a group
// serves a resource at is a view of the same stored objects, so a LIST at one
// of them returns the whole set and examines the kind outright. Keying on the
// version reported a second served version as a coverage gap that does not
// exist, which any multi-version CRD and several built-in groups (autoscaling,
// admissionregistration.k8s.io) hit on an ordinary cluster.
type examinedResourceKey struct {
	group    string
	resource string
}

// queriedResourceKeys parses the query set's triplet keys. A key that is
// not a triplet cannot name a discovered resource, so it is dropped rather than
// kept as a partly-empty identity that could match one.
func queriedResourceKeys(queryable QueryableResources) map[examinedResourceKey]struct{} {
	queried := make(map[examinedResourceKey]struct{}, len(queryable))
	for triplet := range queryable {
		group, _, resource := k8sinterface.StringToResourceGroup(triplet)
		if resource == "" {
			continue
		}
		queried[examinedResourceKey{group: group, resource: resource}] = struct{}{}
	}
	return queried
}

// computeUnexaminedKinds returns the listable resource kinds discovery
// reported that queryable does not include, one entry per kind, sorted by GVR
// triplet. discovered only ever contains real API-server-served kinds (see
// collectDiscoveredResources), so Kubescape's own virtual/external resources
// (host sensor, cloud, RBAC) never appear here and need no filtering.
//
// A kind served at several versions is one coverage gap, not one per version,
// so it is reported at the version an apiserver itself would prefer.
func computeUnexaminedKinds(discovered []discoveredAPIResource, queryable QueryableResources) []cautils.UnexaminedKind {
	queried := queriedResourceKeys(queryable)

	gaps := make(map[examinedResourceKey]discoveredAPIResource, len(discovered))
	for _, candidate := range discovered {
		if !candidate.listable {
			continue
		}
		key := examinedResourceKey{group: candidate.gvr.Group, resource: candidate.gvr.Resource}
		if _, examined := queried[key]; examined {
			continue
		}
		if reported, seen := gaps[key]; seen && !outranksVersion(candidate.gvr.Version, reported.gvr.Version) {
			continue
		}
		gaps[key] = candidate
	}

	var unexamined []cautils.UnexaminedKind
	for _, candidate := range gaps {
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

// outranksVersion reports whether candidate is the version an apiserver would
// prefer over reported, using its own ordering: GA over beta over alpha, then
// by number. The comparison is total even for versions that ordering cannot
// parse, so which of a resource's versions gets reported never depends on the
// order discovery listed them in.
func outranksVersion(candidate, reported string) bool {
	return version.CompareKubeAwareVersionStrings(candidate, reported) > 0
}
