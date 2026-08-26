package resourcehandler

import (
	"sort"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
)

// computeUnexaminedKinds returns the listable resource kinds discovery
// reported that queryable does not include, sorted by GVR triplet. discovered
// only ever contains real API-server-served kinds (see collectDiscoveredResources),
// so Kubescape's own virtual/external resources (host sensor, cloud, RBAC)
// never appear here and need no filtering.
func computeUnexaminedKinds(discovered []discoveredAPIResource, queryable QueryableResources) []cautils.UnexaminedKind {
	var unexamined []cautils.UnexaminedKind
	for _, candidate := range discovered {
		if !candidate.listable {
			continue
		}
		triplet := k8sinterface.GroupVersionResourceToString(&candidate.gvr)
		if _, queried := queryable[triplet]; queried {
			continue
		}
		unexamined = append(unexamined, cautils.UnexaminedKind{
			GroupVersionResource: triplet,
			Kind:                 candidate.kind,
		})
	}
	sort.Slice(unexamined, func(i, j int) bool {
		return unexamined[i].GroupVersionResource < unexamined[j].GroupVersionResource
	})
	return unexamined
}
