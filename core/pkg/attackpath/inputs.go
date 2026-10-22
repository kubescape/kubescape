// Package attackpath chains the four static analysis engines
// (exposure, networkpolicy, rbacgraph, vulnexposure) from a single
// resource-collection pass to produce ranked, end-to-end attack paths.
// Phase 1 ships only this shared input adapter and the two resolvers
// (workload.go, serviceaccount.go); the graph builder, path search,
// and CLI command follow in later phases.
package attackpath

import (
	"fmt"
	"reflect"
	"sort"

	"github.com/kubescape/k8s-interface/workloadinterface"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	exposurepkg "github.com/kubescape/kubescape/v4/core/pkg/exposure"
	"github.com/kubescape/kubescape/v4/core/pkg/networkpolicy"
	"github.com/kubescape/kubescape/v4/core/pkg/rbacgraph"
)

// Inputs holds the typed outputs of all four FromResources adapters,
// produced from a single pass over the scanner's resource map.
type Inputs struct {
	// Exposure engine. Services preserves the decoded input, including duplicates;
	// consult AmbiguousServices before using it to build another index.
	Services  []corev1.Service
	Ingresses []networkingv1.Ingress
	ExpNS     []exposurepkg.NamespaceInfo
	// ExposureIndex retains decoded Gateway API objects for exposure queries.
	// It is nil when conflicting Service definitions prevent a reliable verdict.
	ExposureIndex *exposurepkg.Index
	// AmbiguousServices lists identities with conflicting Service specs in namespace/name
	// order. An unavailable ExposureIndex must not be interpreted as no exposure.
	AmbiguousServices []exposurepkg.ServiceRef

	// NetworkPolicy engine
	Policies []*networkingv1.NetworkPolicy
	NpNS     []networkpolicy.NamespaceInfo

	// RBAC engine
	Roles               []rbacv1.Role
	ClusterRoles        []rbacv1.ClusterRole
	RoleBindings        []rbacv1.RoleBinding
	ClusterRoleBindings []rbacv1.ClusterRoleBinding
	ServiceAccounts     []corev1.ServiceAccount

	// Aggregated decode errors and ambiguity diagnostics, attributed by engine.
	Warnings []string
}

// CollectInputs runs all four FromResources adapters over the same resource
// map in one pass, aggregating their warnings. It also calls Gateway API
// decoding for the exposure engine. A decode failure in any one engine is
// surfaced as a warning; it never aborts the collection.
func CollectInputs(resources map[string]workloadinterface.IMetadata) Inputs {
	var inp Inputs

	// Exposure engine (Services, Ingresses, plain Namespaces).
	svcs, ings, expNS, expErrs := exposurepkg.FromResources(resources)
	inp.Services = svcs
	inp.AmbiguousServices = conflictingServices(svcs)
	inp.Ingresses = ings
	inp.ExpNS = expNS
	for _, e := range expErrs {
		inp.Warnings = append(inp.Warnings, "exposure: "+e.Error())
	}

	// Exposure engine — Gateway API objects (HTTPRoute, GRPCRoute, Gateway).
	routes, gateways, gwErrs := exposurepkg.FromUnstructuredGatewayAPI(resources)
	for _, e := range gwErrs {
		inp.Warnings = append(inp.Warnings, "exposure/gateway: "+e.Error())
	}
	// The resource map does not establish that ReferenceGrants were completely
	// collected. Keep cross-namespace backend authorization undetermined.
	if len(inp.AmbiguousServices) == 0 {
		inp.ExposureIndex = exposurepkg.NewIndex(svcs, ings, routes, gateways, expNS)
	} else {
		for _, ref := range inp.AmbiguousServices {
			inp.Warnings = append(inp.Warnings, fmt.Sprintf("exposure: conflicting Service definitions for %s/%s; exposure index unavailable", ref.Namespace, ref.Name))
		}
	}

	// NetworkPolicy engine.
	policies, npNS, npErrs := networkpolicy.FromResources(resources)
	inp.Policies = policies
	inp.NpNS = npNS
	for _, e := range npErrs {
		inp.Warnings = append(inp.Warnings, "networkpolicy: "+e.Error())
	}

	// RBAC engine.
	roles, crs, rbs, crbs, sas, rbacErrs := rbacgraph.FromResources(resources)
	inp.Roles = roles
	inp.ClusterRoles = crs
	inp.RoleBindings = rbs
	inp.ClusterRoleBindings = crbs
	inp.ServiceAccounts = sas
	for _, e := range rbacErrs {
		inp.Warnings = append(inp.Warnings, "rbacgraph: "+e.Error())
	}

	return inp
}

// conflictingServices never clears a conflict when a later duplicate matches
// one of the definitions: no input order can make that identity unambiguous.
func conflictingServices(services []corev1.Service) []exposurepkg.ServiceRef {
	seen := make(map[exposurepkg.ServiceRef]corev1.Service)
	conflicts := make(map[exposurepkg.ServiceRef]bool)
	for _, svc := range services {
		ref := exposurepkg.ServiceRef{Namespace: svc.Namespace, Name: svc.Name}
		if previous, ok := seen[ref]; ok {
			if !reflect.DeepEqual(previous.Spec, svc.Spec) {
				conflicts[ref] = true
			}
		} else {
			seen[ref] = svc
		}
	}
	var refs []exposurepkg.ServiceRef
	for ref := range conflicts {
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Namespace != refs[j].Namespace {
			return refs[i].Namespace < refs[j].Namespace
		}
		return refs[i].Name < refs[j].Name
	})
	return refs
}
