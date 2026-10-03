package attackpath

import (
	"fmt"
	"sort"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/exposure"
	"github.com/kubescape/kubescape/v4/core/pkg/networkpolicy"
	"github.com/kubescape/kubescape/v4/core/pkg/rbacgraph"
	"github.com/kubescape/kubescape/v4/core/pkg/vulnexposure"
	storagev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// BuildOptions controls which CVE data and severity threshold to use.
type BuildOptions struct {
	// MinCVESeverity is the minimum vulnexposure.Severity to include as a
	// CVE node. Defaults to SeverityHigh when zero.
	MinCVESeverity vulnexposure.Severity
	// VulnsByWorkload is optional CVE data from an in-cluster scanner.
	// When nil, CVE nodes are omitted and paths score lower (no entry vector).
	VulnsByWorkload map[vulnexposure.Workload][]storagev1beta1.Vulnerability
}

// BuildGraph constructs the full attack graph from one resource snapshot.
// It calls all four engines (using the Inputs already collected by
// CollectInputs), the two Phase 1 resolvers, and the SA automount index.
// All edges are added in sorted order so the graph is deterministic.
func BuildGraph(
	resources map[string]workloadinterface.IMetadata,
	inp Inputs,
	opts BuildOptions,
) *Graph {
	if opts.MinCVESeverity == 0 {
		opts.MinCVESeverity = vulnexposure.SeverityHigh
	}

	g := newGraph()

	// --- Build the four engine indexes ---
	expIdx := buildExposureIndex(inp)
	npIdx, _ := networkpolicy.NewIndex(inp.Policies, inp.NpNS)
	rbacIdx := rbacgraph.NewIndex(
		inp.Roles, inp.ClusterRoles,
		inp.RoleBindings, inp.ClusterRoleBindings,
		inp.ServiceAccounts,
	)

	// --- SA automount index (for runs-as edges) ---
	saAutomount := ServiceAccountAutomountIndex(inp.ServiceAccounts)

	// --- Resolve Service → workload backends ---
	serviceBackends := ResolveServiceBackends(inp.Services, resources)

	// --- Resolve workload → ServiceAccount bindings ---
	saBindings := ResolveServiceAccountBindings(resources, saAutomount)

	// --- Static sink node: ClusterAdmin ---
	caNode := Node{ID: nodeID(NodeClusterAdmin, "", "cluster-admin"), Kind: NodeClusterAdmin, Name: "cluster-admin"}
	g.addNode(caNode)

	// --- Static source node: Internet ---
	internetNode := Node{ID: nodeID(NodeInternet, "", ""), Kind: NodeInternet, Name: "Internet"}
	g.addNode(internetNode)

	// --- Layer 1: Internet → Service (via exposure engine) ---
	// Sort services for determinism.
	sortedSvcs := make([]serviceBackendEntry, 0, len(serviceBackends))
	for _, sb := range serviceBackends {
		sortedSvcs = append(sortedSvcs, serviceBackendEntry{sb: sb})
	}
	sort.Slice(sortedSvcs, func(i, j int) bool {
		a, b := sortedSvcs[i].sb, sortedSvcs[j].sb
		if a.ServiceNamespace != b.ServiceNamespace {
			return a.ServiceNamespace < b.ServiceNamespace
		}
		return a.ServiceName < b.ServiceName
	})

	for _, entry := range sortedSvcs {
		sb := entry.sb
		svcRef := exposure.ServiceRef{Namespace: sb.ServiceNamespace, Name: sb.ServiceName}
		paths, unclear := expIdx.ServiceExposure(svcRef)
		if len(paths) == 0 {
			continue // Service is not externally exposed
		}

		svcNode := Node{
			ID:        nodeID(NodeService, sb.ServiceNamespace, sb.ServiceName),
			Kind:      NodeService,
			Namespace: sb.ServiceNamespace,
			Name:      sb.ServiceName,
		}
		g.addNode(svcNode)

		// One Internet→Service edge per exposure path, sorted for determinism.
		sort.Slice(paths, func(i, j int) bool {
			return paths[i].Source < paths[j].Source
		})
		for _, ep := range paths {
			certain := !unclear && isDefinitelyExternal(ep)
			g.addEdge(Edge{
				From:     internetNode.ID,
				To:       svcNode.ID,
				Kind:     EdgeExposes,
				Evidence: fmt.Sprintf("%s via %s", ep.Kind, ep.Source),
				Certain:  certain,
			})
		}

		// --- Layer 2: Service → Workload (via service_workload resolver) ---
		if sb.Headless {
			continue
		}
		for _, wref := range sb.Backends {
			wNode := Node{
				ID:        nodeID(NodeWorkload, wref.Namespace, wref.Name),
				Kind:      NodeWorkload,
				Namespace: wref.Namespace,
				Name:      wref.Name,
			}
			g.addNode(wNode)

			// Evaluate the network hop via the NetworkPolicy engine.
			wEp := networkpolicy.Endpoint{
				Namespace: wref.Namespace,
				Name:      wref.Name,
				Labels:    podTemplateLabelsFromResources(resources, wref),
			}
			npExposure := npIdx.IngressExposure(wEp)
			certain := npExposure.Level >= networkpolicy.ExposureAnyNamespace

			g.addEdge(Edge{
				From:     svcNode.ID,
				To:       wNode.ID,
				Kind:     EdgeNetworkReach,
				Evidence: npExposure.Reason,
				Certain:  certain,
			})

			// --- Layer 3: Workload → CVE (optional, when vuln data present) ---
			if opts.VulnsByWorkload != nil {
				wKey := vulnexposure.Workload{
					Namespace: wref.Namespace,
					Kind:      wref.Kind,
					Name:      wref.Name,
				}
				addCVENodes(g, wNode, opts.VulnsByWorkload[wKey], opts.MinCVESeverity)
			}
		}
	}

	// --- Layer 3: Workload → ServiceAccount (runs-as edges) ---
	for _, binding := range saBindings {
		if !binding.TokenMounted {
			continue // no token → no runs-as edge
		}
		wNode := Node{
			ID:        nodeID(NodeWorkload, binding.Namespace, binding.WorkloadRef.Name),
			Kind:      NodeWorkload,
			Namespace: binding.Namespace,
			Name:      binding.WorkloadRef.Name,
		}
		saNode := Node{
			ID:        nodeID(NodeServiceAccount, binding.Namespace, binding.ServiceAccountName),
			Kind:      NodeServiceAccount,
			Namespace: binding.Namespace,
			Name:      binding.ServiceAccountName,
		}
		g.addNode(saNode)
		g.addEdge(Edge{
			From:     wNode.ID,
			To:       saNode.ID,
			Kind:     EdgeRunsAs,
			Evidence: fmt.Sprintf("serviceAccountName=%s", binding.ServiceAccountName),
			Certain:  true,
		})

		// --- Layer 4: ServiceAccount → ClusterAdmin (via rbacgraph) ---
		subject := rbacgraph.Subject{
			Kind:      rbacgraph.KindServiceAccount,
			Namespace: binding.Namespace,
			Name:      binding.ServiceAccountName,
		}
		result := rbacIdx.AnalyzeEscalation(subject)
		if result.ClusterAdmin {
			certain := !result.Truncated
			evidence := "RBAC escalation reaches cluster-admin"
			if len(result.Reached) > 0 {
				evidence = fmt.Sprintf("via %s", result.Reached[0].Edges[0].Detail)
			}
			g.addEdge(Edge{
				From:     saNode.ID,
				To:       caNode.ID,
				Kind:     EdgeEscalates,
				Evidence: evidence,
				Certain:  certain,
			})
		}
	}

	return g
}

// --- helpers ---

type serviceBackendEntry struct{ sb ServiceBackend }

// buildExposureIndex constructs an exposure.Index from the Inputs.
// Gateway API objects are not re-decoded here in Phase 2 (they require the
// full unstructured resource map); the index is built from Services,
// Ingresses and Namespaces only, same as the MCP service_exposure tool.
func buildExposureIndex(inp Inputs) *exposure.Index {
	// exposure.NewIndex needs routes and gateways; pass nil slices for now —
	// the static Ingress/LoadBalancer/NodePort paths still work, and
	// Gateway API support can be wired in Phase 4 when the full resource
	// map is also passed to BuildGraph.
	idx, _ := exposure.NewIndex(inp.Services, inp.Ingresses, nil, nil, inp.ExpNS)
	return idx
}

// podTemplateLabelsFromResources looks up a workload's pod-template labels
// directly from the resource map, reusing the Phase 1 resolver.
func podTemplateLabelsFromResources(
	resources map[string]workloadinterface.IMetadata,
	ref WorkloadRef,
) map[string]string {
	results := ResolveEndpointsFromResources(resources, []WorkloadRef{ref})
	if len(results) == 1 && results[0].Resolved {
		return results[0].Endpoint.Labels
	}
	return nil
}

// isDefinitelyExternal reports whether an ExposurePath represents a
// mechanism where traffic definitely originates outside the cluster.
// LoadBalancer/NodePort/ExternalIP are marked Certain=false per proposal
// §3.5 until an external-aware networkpolicy matcher exists.
func isDefinitelyExternal(ep exposure.ExposurePath) bool {
	return ep.Kind == exposure.ExposureIngress ||
		ep.Kind == exposure.ExposureHTTPRoute ||
		ep.Kind == exposure.ExposureGRPCRoute
}

// addCVENodes adds a CVE node and Workload→CVE edge for each vulnerability
// at or above minSeverity, sorted by CVE ID for determinism.
func addCVENodes(
	g *Graph,
	wNode Node,
	vulns []storagev1beta1.Vulnerability,
	minSeverity vulnexposure.Severity,
) {
	type cveEntry struct {
		id       string
		severity string
		fix      bool
	}
	var entries []cveEntry
	for _, v := range vulns {
		if vulnexposure.ParseSeverity(v.Severity) < minSeverity {
			continue
		}
		fixable := len(v.Fix.Versions) > 0 && v.Fix.State == "fixed"
		entries = append(entries, cveEntry{id: v.ID, severity: v.Severity, fix: fixable})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].id < entries[j].id })

	for _, e := range entries {
		cveNode := Node{
			ID:   nodeID(NodeCVE, "", e.id),
			Kind: NodeCVE,
			Name: e.id,
		}
		g.addNode(cveNode)
		evidence := fmt.Sprintf("severity=%s fix=%v", e.severity, e.fix)
		g.addEdge(Edge{
			From:     wNode.ID,
			To:       cveNode.ID,
			Kind:     EdgeVulnerable,
			Evidence: evidence,
			Certain:  true,
		})
	}
}
