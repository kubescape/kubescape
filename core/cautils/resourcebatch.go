package cautils

import (
	"sort"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
)

// ClusterScope is the scope of the resources every other scope depends on:
// cluster-scoped Kubernetes objects and external (cloud / host scanner /
// API server) objects. A rule evaluated against any namespace may need to
// correlate against them, so the ClusterScope batch stays resident for the
// whole evaluation while namespace batches come and go.
const ClusterScope = "clusterScope"

const defaultLargeClusterSize = 2500

// IsLargeCluster reports whether a cluster of clusterSize resources is large
// enough to be evaluated one namespace at a time rather than as a single
// cluster-wide input. Below the threshold the whole cluster is a single batch,
// which keeps cross-namespace rules working on the clusters where the memory
// cost of doing so is acceptable.
//
// The threshold is overridable through the LARGE_CLUSTER_SIZE environment
// variable.
func IsLargeCluster(clusterSize int) bool {
	largeClusterSize, _ := ParseIntEnvVar("LARGE_CLUSTER_SIZE", defaultLargeClusterSize)
	return clusterSize > largeClusterSize
}

// ResourceScope returns the scope a resource belongs to: its namespace for
// namespace-scoped objects, its own name for a Namespace object (so that a
// namespace is evaluated together with the resources it contains), and
// ClusterScope for everything else.
func ResourceScope(obj workloadinterface.IMetadata) string {
	if k8sinterface.IsResourceInNamespaceScope(obj.GetKind()) {
		return obj.GetNamespace()
	}
	if obj.GetKind() == "Namespace" {
		return obj.GetName()
	}
	return ClusterScope
}

// ResourceBatch is a self-contained unit of evaluation input: every resource
// belonging to a single scope, together with the indexes needed to select the
// subset a policy rule matches. A batch owns its objects, so once the last
// rule has been evaluated against it the batch can be released.
type ResourceBatch struct {
	// Scope is the namespace this batch holds, or ClusterScope.
	Scope string
	// K8SResources indexes the batch's Kubernetes objects by GVR triplet.
	K8SResources K8SResources
	// ExternalResources indexes the batch's non-Kubernetes objects. Only the
	// ClusterScope batch carries these.
	ExternalResources ExternalResources
	// AllResources holds the batch's objects by resource ID.
	AllResources map[string]workloadinterface.IMetadata
}

// NewResourceBatch returns an empty batch for the given scope.
func NewResourceBatch(scope string) *ResourceBatch {
	return &ResourceBatch{
		Scope:             scope,
		K8SResources:      make(K8SResources),
		ExternalResources: make(ExternalResources),
		AllResources:      make(map[string]workloadinterface.IMetadata),
	}
}

// Len returns the number of resources in the batch.
func (batch *ResourceBatch) Len() int {
	return len(batch.AllResources)
}

// PartitionResources splits a scan's resources into the resident ClusterScope
// batch and zero or more namespace batches, sorted by namespace for
// deterministic evaluation order.
//
// On clusters at or below the large-cluster threshold no namespace batches are
// produced: every resource lands in the resident batch, which reproduces the
// single cluster-wide evaluation input used for small clusters.
//
// Resource IDs present in the indexes but missing from allResources are
// skipped rather than materialised as nil entries.
func PartitionResources(k8sResources K8SResources, externalResources ExternalResources, allResources map[string]workloadinterface.IMetadata) (resident *ResourceBatch, batches []*ResourceBatch) {
	resident = NewResourceBatch(ClusterScope)

	for groupResource, ids := range externalResources {
		for _, id := range ids {
			obj, ok := allResources[id]
			if !ok {
				continue
			}
			resident.ExternalResources[groupResource] = append(resident.ExternalResources[groupResource], id)
			resident.AllResources[id] = obj
		}
	}

	byNamespace := IsLargeCluster(len(allResources))
	namespaced := make(map[string]*ResourceBatch)

	for groupResource, ids := range k8sResources {
		for _, id := range ids {
			obj, ok := allResources[id]
			if !ok {
				continue
			}

			batch := resident
			if byNamespace {
				if scope := ResourceScope(obj); scope != ClusterScope {
					batch, ok = namespaced[scope]
					if !ok {
						batch = NewResourceBatch(scope)
						namespaced[scope] = batch
					}
				}
			}

			batch.K8SResources[groupResource] = append(batch.K8SResources[groupResource], id)
			batch.AllResources[id] = obj
		}
	}

	scopes := make([]string, 0, len(namespaced))
	for scope := range namespaced {
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)

	batches = make([]*ResourceBatch, 0, len(scopes))
	for _, scope := range scopes {
		batches = append(batches, namespaced[scope])
	}

	return resident, batches
}
