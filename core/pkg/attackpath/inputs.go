// Package attackpath chains the four static analysis engines
// (exposure, networkpolicy, rbacgraph, vulnexposure) from a single
// resource-collection pass to produce ranked, end-to-end attack paths.
// Phase 1 ships only this shared input adapter and the two resolvers
// (workload.go, serviceaccount.go); the graph builder, path search,
// and CLI command follow in later phases.
package attackpath

import (
    "github.com/kubescape/k8s-interface/workloadinterface"
    corev1 "k8s.io/api/core/v1"
    networkingv1 "k8s.io/api/networking/v1"
    rbacv1 "k8s.io/api/rbac/v1"

    "github.com/kubescape/kubescape/v4/core/pkg/exposure"
    "github.com/kubescape/kubescape/v4/core/pkg/networkpolicy"
    "github.com/kubescape/kubescape/v4/core/pkg/rbacgraph"
)

// Inputs holds the typed outputs of all four FromResources adapters,
// produced from a single pass over the scanner's resource map.
type Inputs struct {
    // Exposure engine
    Services   []corev1.Service
    Ingresses  []networkingv1.Ingress
    ExpNS      []exposure.NamespaceInfo

    // NetworkPolicy engine
    Policies []* networkingv1.NetworkPolicy
    NpNS     []networkpolicy.NamespaceInfo

    // RBAC engine
    Roles               []rbacv1.Role
    ClusterRoles        []rbacv1.ClusterRole
    RoleBindings        []rbacv1.RoleBinding
    ClusterRoleBindings []rbacv1.ClusterRoleBinding
    ServiceAccounts     []corev1.ServiceAccount

    // Aggregated decode errors from all four adapters, attributed by engine.
    Warnings []string
}

// CollectInputs runs all four FromResources adapters over the same resource
// map in one pass, aggregating their warnings. It also calls Gateway API
// decoding for the exposure engine. A decode failure in any one engine is
// surfaced as a warning; it never aborts the collection.
func CollectInputs(resources map[string]workloadinterface.IMetadata) Inputs {
    var inp Inputs

    // Exposure engine (Services, Ingresses, plain Namespaces).
    svcs, ings, expNS, expErrs := exposure.FromResources(resources)
    inp.Services = svcs
    inp.Ingresses = ings
    inp.ExpNS = expNS
    for _, e := range expErrs {
        inp.Warnings = append(inp.Warnings, "exposure: "+e.Error())
    }

    // Exposure engine — Gateway API objects (HTTPRoute, GRPCRoute, Gateway).
    _, _, gwErrs := exposure.FromUnstructuredGatewayAPI(resources)
    for _, e := range gwErrs {
        inp.Warnings = append(inp.Warnings, "exposure/gateway: "+e.Error())
    }
    // Note: gateway routes/gateways are kept inside the exposure.Index;
    // CollectInputs does not need to carry them separately — the Index
    // is built from them at graph-build time by the caller.

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
