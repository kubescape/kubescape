// Package attackpath chains the four static analysis engines
// (exposure, networkpolicy, rbacgraph, vulnexposure) from a single
// resource-collection pass to produce ranked, end-to-end attack paths.
// Phase 1 ships only this shared input adapter and the two resolvers
// (workload.go, serviceaccount.go); the graph builder, path search,
// and CLI command follow in later phases.
package attackpath

import (
	"fmt"
	"maps"
	"reflect"
	"sort"
	"strings"

	"github.com/kubescape/k8s-interface/workloadinterface"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

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
	// It is nil when conflicting definitions or unsupported Ingress API versions
	// prevent a reliable verdict; callers must handle an unavailable index and
	// consult Warnings. Only networking.k8s.io/v1 Ingress backends are decoded.
	ExposureIndex *exposurepkg.Index
	// AmbiguousServices lists identities with conflicting Service specs in namespace/name
	// order. An unavailable ExposureIndex must not be interpreted as no exposure.
	AmbiguousServices []exposurepkg.ServiceRef
	// AmbiguousGateways and AmbiguousNamespaces identify conflicting exposure
	// inputs in sorted order, ignoring metadata unrelated to exposure analysis.
	AmbiguousGateways   []exposurepkg.ServiceRef
	AmbiguousNamespaces []string
	AmbiguousIngresses  []exposurepkg.ServiceRef
	// AmbiguousRoutes contains sorted Kind/namespace/name Gateway API identities.
	AmbiguousRoutes []string

	// NetworkPolicy engine. Callers MUST check NetworkPolicyUnavailable before
	// evaluation: conflicting definitions are retained, not unioned or dropped.
	Policies                 []*networkingv1.NetworkPolicy
	NpNS                     []networkpolicy.NamespaceInfo
	NetworkPolicyUnavailable bool
	AmbiguousPolicies        []string // sorted Kind/namespace/name identities

	// RBAC engine. Callers MUST check RBACUnavailable before evaluation;
	// conflicting definitions remain present for diagnosis, not authorization.
	RBACUnavailable     bool
	AmbiguousRBAC       []string // sorted Kind/namespace/name identities
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
	resources = supportedInputResources(resources)

	// Exposure engine (Services, Ingresses, plain Namespaces).
	exposureResources := make(map[string]workloadinterface.IMetadata)
	var unsupportedIngressWarnings []string
	for id, res := range resources {
		if res == nil {
			continue
		}
		apiVersion, _ := res.GetObject()["apiVersion"].(string)
		group, version, qualified := strings.Cut(apiVersion, "/")
		switch res.GetKind() {
		case "Service", "Namespace":
			if !qualified && apiVersion != "" {
				exposureResources[id] = res
			}
		case "Ingress":
			if qualified && (group == "networking.k8s.io" || group == "extensions") && version != "" {
				if apiVersion == "networking.k8s.io/v1" {
					exposureResources[id] = res
				} else {
					// Legacy backends have a different wire shape. Decoding them
					// as v1 silently drops serviceName/servicePort and spec.backend.
					unsupportedIngressWarnings = append(unsupportedIngressWarnings, fmt.Sprintf("exposure: unsupported Ingress API version %s for %s/%s; exposure index unavailable", apiVersion, res.GetNamespace(), res.GetName()))
				}
			}
		}
	}
	sort.Strings(unsupportedIngressWarnings)
	inp.Warnings = append(inp.Warnings, unsupportedIngressWarnings...)
	svcs, ings, expNS, expErrs := exposurepkg.FromResources(exposureResources)
	inp.Services = svcs
	inp.AmbiguousServices = conflictingServices(svcs)
	inp.Ingresses = ings
	seenIngresses := make(map[exposurepkg.ServiceRef]networkingv1.IngressSpec)
	ingressConflicts := make(map[exposurepkg.ServiceRef]bool)
	for _, ing := range ings {
		ref := exposurepkg.ServiceRef{Namespace: ing.Namespace, Name: ing.Name}
		if previous, exists := seenIngresses[ref]; exists {
			if !reflect.DeepEqual(previous, ing.Spec) {
				ingressConflicts[ref] = true
			}
		} else {
			seenIngresses[ref] = ing.Spec
		}
	}
	inp.AmbiguousIngresses = sortedExposureRefs(ingressConflicts)
	inp.ExpNS = expNS
	for _, e := range expErrs {
		inp.Warnings = append(inp.Warnings, "exposure: "+e.Error())
	}

	// Exposure engine — Gateway API objects (HTTPRoute, GRPCRoute, Gateway).
	routes, gateways, gwErrs := exposurepkg.FromUnstructuredGatewayAPI(resources)
	for _, e := range gwErrs {
		inp.Warnings = append(inp.Warnings, "exposure/gateway: "+e.Error())
	}
	seenGateways := make(map[exposurepkg.ServiceRef]any)
	gatewayConflicts := make(map[exposurepkg.ServiceRef]bool)
	for _, gw := range gateways {
		ref := exposurepkg.ServiceRef{Namespace: gw.Namespace, Name: gw.Name}
		if previous, exists := seenGateways[ref]; exists {
			if !reflect.DeepEqual(previous, gw) {
				gatewayConflicts[ref] = true
			}
		} else {
			seenGateways[ref] = gw
		}
	}
	inp.AmbiguousGateways = sortedExposureRefs(gatewayConflicts)
	seenRoutes := make(map[string]any)
	routeConflicts := make(map[string]bool)
	for _, route := range routes {
		key := route.Kind + "/" + route.Namespace + "/" + route.Name
		if previous, exists := seenRoutes[key]; exists {
			if !reflect.DeepEqual(previous, route) {
				routeConflicts[key] = true
			}
		} else {
			seenRoutes[key] = route
		}
	}
	for key := range routeConflicts {
		inp.AmbiguousRoutes = append(inp.AmbiguousRoutes, key)
	}
	sort.Strings(inp.AmbiguousRoutes)
	seenNamespaces := make(map[string]map[string]string)
	namespaceConflicts := make(map[string]bool)
	for _, ns := range expNS {
		if previous, exists := seenNamespaces[ns.Name]; exists {
			if !maps.Equal(previous, ns.Labels) {
				namespaceConflicts[ns.Name] = true
			}
		} else {
			seenNamespaces[ns.Name] = ns.Labels
		}
	}
	for name := range namespaceConflicts {
		inp.AmbiguousNamespaces = append(inp.AmbiguousNamespaces, name)
	}
	sort.Strings(inp.AmbiguousNamespaces)
	// The resource map does not establish that ReferenceGrants were completely
	// collected. Keep cross-namespace backend authorization undetermined.
	if len(unsupportedIngressWarnings) == 0 && len(inp.AmbiguousServices) == 0 && len(inp.AmbiguousGateways) == 0 && len(inp.AmbiguousNamespaces) == 0 && len(inp.AmbiguousIngresses) == 0 && len(inp.AmbiguousRoutes) == 0 {
		inp.ExposureIndex = exposurepkg.NewIndex(svcs, ings, routes, gateways, expNS)
	} else {
		for _, ref := range inp.AmbiguousServices {
			inp.Warnings = append(inp.Warnings, fmt.Sprintf("exposure: conflicting Service definitions for %s/%s; exposure index unavailable", ref.Namespace, ref.Name))
		}
		for _, ref := range inp.AmbiguousGateways {
			inp.Warnings = append(inp.Warnings, fmt.Sprintf("exposure: conflicting Gateway definitions for %s/%s; exposure index unavailable", ref.Namespace, ref.Name))
		}
		for _, name := range inp.AmbiguousNamespaces {
			inp.Warnings = append(inp.Warnings, fmt.Sprintf("exposure: conflicting Namespace labels for %s; exposure index unavailable", name))
		}
		for _, ref := range inp.AmbiguousIngresses {
			inp.Warnings = append(inp.Warnings, fmt.Sprintf("exposure: conflicting Ingress definitions for %s/%s; exposure index unavailable", ref.Namespace, ref.Name))
		}
		for _, key := range inp.AmbiguousRoutes {
			kind, ref, _ := strings.Cut(key, "/")
			inp.Warnings = append(inp.Warnings, fmt.Sprintf("exposure: conflicting %s definitions for %s; exposure index unavailable", kind, ref))
		}
	}

	// NetworkPolicy engine.
	policies, npNS, npErrs := networkpolicy.FromResources(resources)
	inp.Policies, inp.AmbiguousPolicies = coalesceAnalysisDefinitions(policies, func(p *networkingv1.NetworkPolicy) (string, any) {
		return "NetworkPolicy/" + p.Namespace + "/" + p.Name, p.Spec
	})
	inp.NetworkPolicyUnavailable = len(inp.AmbiguousPolicies) > 0
	for _, identity := range inp.AmbiguousPolicies {
		inp.Warnings = append(inp.Warnings, "networkpolicy: conflicting definitions for "+identity+"; NetworkPolicy evaluation unavailable")
	}
	inp.NpNS = npNS
	for _, e := range npErrs {
		inp.Warnings = append(inp.Warnings, "networkpolicy: "+e.Error())
	}

	// RBAC engine.
	roles, crs, rbs, crbs, sas, rbacErrs := rbacgraph.FromResources(resources)
	var conflicts []string
	inp.Roles, conflicts = coalesceAnalysisDefinitions(roles, func(r rbacv1.Role) (string, any) {
		return "Role/" + r.Namespace + "/" + r.Name, r.Rules
	})
	inp.AmbiguousRBAC = append(inp.AmbiguousRBAC, conflicts...)
	inp.ClusterRoles, conflicts = coalesceAnalysisDefinitions(crs, func(r rbacv1.ClusterRole) (string, any) {
		return "ClusterRole//" + r.Name, struct {
			Rules       []rbacv1.PolicyRule
			Aggregation *rbacv1.AggregationRule
			Labels      map[string]string
		}{r.Rules, r.AggregationRule, r.Labels}
	})
	inp.AmbiguousRBAC = append(inp.AmbiguousRBAC, conflicts...)
	inp.RoleBindings, conflicts = coalesceAnalysisDefinitions(rbs, func(r rbacv1.RoleBinding) (string, any) {
		return "RoleBinding/" + r.Namespace + "/" + r.Name, struct {
			RoleRef  rbacv1.RoleRef
			Subjects []rbacv1.Subject
		}{r.RoleRef, r.Subjects}
	})
	inp.AmbiguousRBAC = append(inp.AmbiguousRBAC, conflicts...)
	inp.ClusterRoleBindings, conflicts = coalesceAnalysisDefinitions(crbs, func(r rbacv1.ClusterRoleBinding) (string, any) {
		return "ClusterRoleBinding//" + r.Name, struct {
			RoleRef  rbacv1.RoleRef
			Subjects []rbacv1.Subject
		}{r.RoleRef, r.Subjects}
	})
	inp.AmbiguousRBAC = append(inp.AmbiguousRBAC, conflicts...)
	sort.Strings(inp.AmbiguousRBAC)
	inp.RBACUnavailable = len(inp.AmbiguousRBAC) > 0
	for _, identity := range inp.AmbiguousRBAC {
		inp.Warnings = append(inp.Warnings, "rbacgraph: conflicting definitions for "+identity+"; RBAC evaluation unavailable")
	}
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
	return sortedExposureRefs(conflicts)
}

func sortedExposureRefs(conflicts map[exposurepkg.ServiceRef]bool) []exposurepkg.ServiceRef {
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

// supportedInputResources validates identity before the adapters dispatch by
// kind. Custom resources may reuse built-in kind names with different schemas.
func supportedInputResources(resources map[string]workloadinterface.IMetadata) map[string]workloadinterface.IMetadata {
	filtered := make(map[string]workloadinterface.IMetadata)
	for key, res := range resources {
		if res == nil {
			continue
		}
		apiVersion, _ := res.GetObject()["apiVersion"].(string)
		gv, err := schema.ParseGroupVersion(apiVersion)
		if err != nil || gv.Version == "" {
			continue
		}
		allowed := false
		switch res.GetKind() {
		case "Service", "Namespace", "ServiceAccount":
			allowed = gv.Group == ""
		case "Ingress", "NetworkPolicy":
			// Preserve the historical extensions API group for both kinds.
			allowed = gv.Group == "networking.k8s.io" || gv.Group == "extensions"
		case "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding":
			allowed = gv.Group == "rbac.authorization.k8s.io"
		case "Gateway", "HTTPRoute", "GRPCRoute":
			allowed = gv.Group == "gateway.networking.k8s.io"
		}
		if allowed {
			filtered[key] = res
		}
	}
	return filtered
}

// coalesceAnalysisDefinitions retains each distinct definition once and marks
// identities with multiple definitions. Callers must disable the engine on any
// conflict: retaining conflicting policies must never imply an allow-rule union.
func coalesceAnalysisDefinitions[T any](items []T, definition func(T) (string, any)) ([]T, []string) {
	seen := make(map[string][]any)
	var unique []T
	for _, item := range items {
		identity, data := definition(item)
		duplicate := false
		for _, previous := range seen[identity] {
			if reflect.DeepEqual(previous, data) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			seen[identity] = append(seen[identity], data)
			unique = append(unique, item)
		}
	}
	var conflicts []string
	for identity, definitions := range seen {
		if len(definitions) > 1 {
			conflicts = append(conflicts, identity)
		}
	}
	sort.Strings(conflicts)
	return unique, conflicts
}
