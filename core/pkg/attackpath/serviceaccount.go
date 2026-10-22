package attackpath

import (
	"slices"
	"strings"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/vulnexposure"
)

// ServiceAccountBinding records which ServiceAccount a workload runs as,
// and whether the token is actually mounted (which determines whether
// compromising the workload yields a usable token).
type ServiceAccountBinding struct {
	WorkloadRef WorkloadRef
	// ServiceAccountName is the resolved serviceAccountName.
	// An omitted workload field resolves to "default"; skipped bindings leave this empty.
	ServiceAccountName string
	// Namespace is the workload's namespace; the SA is always in the same one.
	Namespace string
	// TokenMounted is true when the shared identity resolver establishes token
	// access. When TokenUnknown is true, false is not evidence of no access.
	TokenMounted bool
	// TokenUnknown covers incomplete or malformed input and environment-dependent
	// mount paths. It is false if another mount or automatic injection proves access.
	TokenUnknown bool
	// Skipped is true when the workload's object could not be decoded for
	// SA resolution, or has no ServiceAccount identity (a static mirror Pod).
	Skipped    bool
	SkipReason string
}

// ResolveServiceAccountBindings resolves every workload in the resource
// map to its ServiceAccount and token-mount status, in resource-ID order
// for determinism.
// saAutomountByNsName is a map of "namespace/name" → *bool reflecting
// each ServiceAccount's own automountServiceAccountToken setting;
// a present key with a nil pointer uses the Kubernetes default (true).
// A missing key leaves token access unknown unless pod settings or mounts decide it.
func ResolveServiceAccountBindings(
	resources map[string]workloadinterface.IMetadata,
	saAutomountByNsName map[string]*bool,
) []ServiceAccountBinding {
	// Collect workload resources (kinds we know about) in ID order.
	type entry struct {
		id  string
		res workloadinterface.IMetadata
	}
	var entries []entry
	for id, r := range resources {
		if !isSupportedWorkloadResource(r) {
			continue
		}
		entries = append(entries, entry{id: id, res: r})
	}
	// Sort by ID for determinism (mirrors rbacgraph.FromResources).
	slices.SortFunc(entries, func(a, b entry) int {
		if a.id < b.id {
			return -1
		}
		if a.id > b.id {
			return 1
		}
		return 0
	})

	// Adapt the batch index once; both APIs use the same identity and token rules.
	index := &ServiceAccountIndex{automount: make(map[serviceAccountKey]*bool, len(saAutomountByNsName))}
	for key, value := range saAutomountByNsName {
		namespace, name, found := strings.Cut(key, "/")
		if found {
			index.automount[serviceAccountKey{namespace, name}] = value
		}
	}
	var out []ServiceAccountBinding
	for _, e := range entries {
		r := e.res
		ref := WorkloadRef{Namespace: r.GetNamespace(), Kind: r.GetKind(), Name: r.GetName()}
		resolution := ResolveServiceAccount(vulnexposure.Workload{Namespace: ref.Namespace, Kind: ref.Kind, Name: ref.Name}, r.GetObject(), index)
		out = append(out, ServiceAccountBinding{
			WorkloadRef: ref, ServiceAccountName: resolution.Name, Namespace: resolution.Namespace,
			TokenMounted: resolution.Token == TokenMounted, TokenUnknown: resolution.Token == TokenUnknown,
			Skipped: !resolution.Resolved, SkipReason: resolution.Reason,
		})
	}
	return out
}
