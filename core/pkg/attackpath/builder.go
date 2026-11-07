package attackpath

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/kubescape/k8s-interface/workloadinterface"
	exposurepkg "github.com/kubescape/kubescape/v4/core/pkg/exposure"
	"github.com/kubescape/kubescape/v4/core/pkg/networkpolicy"
	"github.com/kubescape/kubescape/v4/core/pkg/rbacgraph"
	"github.com/kubescape/kubescape/v4/core/pkg/vulnexposure"
	storagev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// BuildOptions controls which CVE data and severity threshold to use.
type BuildOptions struct {
	// MinCVESeverity is the minimum vulnexposure.Severity to attach to a
	// workload node. Defaults to SeverityHigh when zero.
	MinCVESeverity vulnexposure.Severity
	// VulnsByWorkload is optional CVE data from an in-cluster scanner.
	// When nil, workload nodes carry no CVEs, paths score lower (no known
	// entry vector) and Graph.HasVulnerabilityData is false.
	VulnsByWorkload map[vulnexposure.Workload][]storagev1beta1.Vulnerability
	// IngressControllers names the workloads whose pods originate traffic for
	// Ingress and Gateway API exposure (the ingress controller or the Gateway
	// data plane). They are the source of the Service -> workload network hop.
	// When empty, a backend that no NetworkPolicy isolates is still reachable
	// (default allow), but a backend that is isolated gets an uncertain hop:
	// the model cannot prove or refute that the controller is admitted.
	IngressControllers []WorkloadRef
}

type hopVerdict int

const (
	hopUnknown hopVerdict = iota
	hopAllowed
	hopDenied
)

// builder carries the state shared by the layers of BuildGraph.
type builder struct {
	g         *Graph
	resources map[string]workloadinterface.IMetadata
	inp       Inputs
	opts      BuildOptions

	npIdx   *networkpolicy.Index // nil when NetworkPolicy evaluation is unavailable
	rbacIdx *rbacgraph.Index     // nil when RBAC evaluation is unavailable

	workloadObjs map[WorkloadRef]map[string]any
	endpoints    map[WorkloadRef]WorkloadEndpointResult

	controllers         []networkpolicy.Endpoint
	controllersResolved bool
	controllersPartial  bool // a configured controller could not be resolved
}

// BuildGraph constructs the full attack graph from one resource snapshot.
// It consumes the Inputs already collected by CollectInputs (including its
// ExposureIndex, availability flags and warnings), the Phase 1 resolvers and
// the ServiceAccount automount index.
//
// Layers: Internet -> Service (exposure), Service -> Workload (NetworkPolicy
// evaluated against the real source and the Service's target ports),
// Workload -> ServiceAccount (token mount), ServiceAccount -> ClusterAdmin
// (RBAC escalation). CVEs are attached to workload nodes.
//
// Nothing is promoted or dropped silently: engine gaps become Warnings,
// individually skipped objects become Skipped, and anything an engine could not
// decide becomes an edge with Certain=false. All edges are added in sorted
// order so the graph is byte-identical across runs.
func BuildGraph(
	resources map[string]workloadinterface.IMetadata,
	inp Inputs,
	opts BuildOptions,
) *Graph {
	if opts.MinCVESeverity == 0 {
		opts.MinCVESeverity = vulnexposure.SeverityHigh
	}
	b := &builder{
		g:            newGraph(),
		resources:    resources,
		inp:          inp,
		opts:         opts,
		workloadObjs: indexWorkloadObjects(resources),
	}
	g := b.g
	g.HasVulnerabilityData = opts.VulnsByWorkload != nil
	g.Warnings = append(g.Warnings, inp.Warnings...)

	internet := Node{ID: nodeID(NodeInternet, "", ""), Kind: NodeInternet, Name: "Internet"}
	clusterAdmin := Node{ID: nodeID(NodeClusterAdmin, "", "cluster-admin"), Kind: NodeClusterAdmin, Name: "cluster-admin"}
	g.addNode(internet)
	g.addNode(clusterAdmin)

	b.initEngines()
	b.addExposureLayer(internet)
	b.addIdentityLayer(clusterAdmin)

	g.finalize()
	return g
}

// initEngines builds the engine indexes the collected Inputs allow and records
// a warning for each engine that cannot be trusted.
func (b *builder) initEngines() {
	if b.inp.ExposureIndex == nil {
		b.g.warn("exposure analysis unavailable: no Internet -> Service edges were built")
	}

	if b.inp.NetworkPolicyUnavailable {
		b.g.warn("NetworkPolicy evaluation unavailable: every network hop is reported as uncertain")
	} else {
		idx, errs := networkpolicy.NewIndex(b.inp.Policies, b.inp.NpNS)
		if len(errs) > 0 {
			// A policy dropped from the index can turn a real Denied into a
			// false Allowed, so the index is not used at all.
			for _, err := range errs {
				b.g.warn("networkpolicy: " + err.Error())
			}
			b.g.warn("NetworkPolicy evaluation unreliable: every network hop is reported as uncertain")
		} else {
			b.npIdx = idx
		}
	}

	if b.inp.RBACUnavailable {
		b.g.warn("RBAC evaluation unavailable: no ServiceAccount -> cluster-admin edges were built")
	} else {
		b.rbacIdx = rbacgraph.NewIndex(
			b.inp.Roles, b.inp.ClusterRoles,
			b.inp.RoleBindings, b.inp.ClusterRoleBindings,
			b.inp.ServiceAccounts,
		)
	}
}

// --- Layers 1 and 2: Internet -> Service -> Workload ---

func (b *builder) addExposureLayer(internet Node) {
	expIdx := b.inp.ExposureIndex
	if expIdx == nil {
		return
	}
	services := make(map[exposurepkg.ServiceRef]*corev1.Service, len(b.inp.Services))
	for i := range b.inp.Services {
		svc := &b.inp.Services[i]
		ref := exposurepkg.ServiceRef{Namespace: svc.Namespace, Name: svc.Name}
		if _, dup := services[ref]; !dup {
			services[ref] = svc
		}
	}

	done := make(map[exposurepkg.ServiceRef]bool)
	// ResolveServiceBackends returns Services in namespace/name order.
	for _, sb := range ResolveServiceBackends(b.inp.Services, b.resources) {
		ref := exposurepkg.ServiceRef{Namespace: sb.ServiceNamespace, Name: sb.ServiceName}
		if done[ref] {
			continue
		}
		done[ref] = true

		paths, unclear := expIdx.ServiceExposure(ref)
		if len(paths) == 0 && !unclear {
			continue // not externally exposed
		}
		svcNode := Node{
			ID:        nodeID(NodeService, sb.ServiceNamespace, sb.ServiceName),
			Kind:      NodeService,
			Namespace: sb.ServiceNamespace,
			Name:      sb.ServiceName,
		}
		b.g.addNode(svcNode)
		ingressLike, otherExposure := b.addExposureEdges(internet.ID, svcNode.ID, paths, unclear)
		b.addBackendEdges(sb, services[ref], svcNode.ID, ingressLike, otherExposure)
	}
}

// addExposureEdges adds the Internet -> Service edges. Exposure through an
// Ingress or Gateway route is a certain edge. LoadBalancer, NodePort and
// externalIPs exposure is uncertain in v1 (proposal §3.5), and so is an
// exposure the engine reported as unclear: the unclear flag adds its own
// uncertain edge and does not demote the paths the engine did confirm.
// It reports whether an ingress-like path exists and whether any other
// (direct or undetermined) exposure exists.
func (b *builder) addExposureEdges(from, to NodeID, paths []exposurepkg.ExposurePath, unclear bool) (ingressLike, otherExposure bool) {
	paths = slices.Clone(paths)
	slices.SortFunc(paths, func(a, c exposurepkg.ExposurePath) int {
		if r := cmp.Compare(a.Kind, c.Kind); r != 0 {
			return r
		}
		if r := cmp.Compare(a.Source, c.Source); r != 0 {
			return r
		}
		return cmp.Compare(a.Host, c.Host)
	})
	for _, ep := range paths {
		switch ep.Kind {
		case exposurepkg.ExposureIngress, exposurepkg.ExposureHTTPRoute, exposurepkg.ExposureGRPCRoute:
			ingressLike = true
			b.g.addEdge(Edge{From: from, To: to, Kind: EdgeExposes, Evidence: exposureEvidence(ep), Certain: true})
		default:
			otherExposure = true
			b.g.addEdge(Edge{
				From: from, To: to, Kind: EdgeExposes, Certain: false,
				Evidence: exposureEvidence(ep) + " (external source not modelled)",
			})
		}
	}
	if unclear {
		otherExposure = true
		b.g.addEdge(Edge{
			From: from, To: to, Kind: EdgeExposes, Certain: false,
			Evidence: "exposure undetermined: cross-namespace route reference without ReferenceGrant data",
		})
	}
	return ingressLike, otherExposure
}

func exposureEvidence(ep exposurepkg.ExposurePath) string {
	s := fmt.Sprintf("%s %s", ep.Kind, ep.Source)
	if ep.Host != "" {
		s += " host " + ep.Host
	}
	return s
}

func (b *builder) addBackendEdges(sb ServiceBackend, svc *corev1.Service, svcID NodeID, ingressLike, otherExposure bool) {
	svcName := sb.ServiceNamespace + "/" + sb.ServiceName
	if sb.Selectorless {
		b.g.skip(fmt.Sprintf("Service %s is externally exposed but has no selector; its backends cannot be inferred", svcName))
		return
	}
	for _, ref := range sb.UnresolvedBackends {
		b.g.skip(fmt.Sprintf("Service %s: backend %s %s/%s has conflicting or malformed pod labels and was not resolved", svcName, ref.Kind, ref.Namespace, ref.Name))
	}
	if len(sb.Backends) == 0 && len(sb.UnresolvedBackends) == 0 {
		b.g.skip(fmt.Sprintf("Service %s is externally exposed but its selector matches no collected workload", svcName))
	}
	for _, ref := range sb.Backends {
		verdict, evidence := b.networkHop(svc, ref, ingressLike)
		certain := verdict == hopAllowed
		if verdict == hopDenied {
			if !otherExposure {
				continue // confirmed denied: not an edge
			}
			// The hop is denied for the ingress controller, but the Service is
			// also exposed through a source this model cannot evaluate.
			certain = false
			evidence += "; external-source reachability is not modelled"
		}
		b.g.addNode(b.workloadNode(ref))
		b.g.addEdge(Edge{From: svcID, To: workloadNodeID(ref), Kind: EdgeNetworkReach, Evidence: evidence, Certain: certain})
	}
}

// networkHop decides the Service -> workload hop against the actual source of
// the exposure and the Service's actual target ports, not against the widest
// source class a policy admits (that would call a policy allowing port 9090
// from anywhere a certain hop for an Ingress that targets port 8080).
//
//   - Not ingress-like (LoadBalancer/NodePort/ExternalIP): always uncertain.
//     networkpolicy.Endpoint models a pod, so an external source cannot be
//     evaluated without wrongly admitting it through an empty namespaceSelector.
//   - Backend not isolated for ingress: allowed, any source, any port.
//   - Isolated, ingress controller not identified: uncertain.
//   - Isolated, controller identified: Reaches is evaluated per Service target
//     port. Allowed on every port is certain; denied on every port is a
//     confirmed denial; anything else is uncertain, because the exposure path
//     does not say which Service port it targets.
func (b *builder) networkHop(svc *corev1.Service, ref WorkloadRef, ingressLike bool) (hopVerdict, string) {
	if !ingressLike {
		return hopUnknown, "external source (LoadBalancer/NodePort/ExternalIP) is not modelled by NetworkPolicy matching"
	}
	if b.npIdx == nil {
		return hopUnknown, "NetworkPolicy evaluation unavailable"
	}
	if svc == nil {
		return hopUnknown, "Service definition unavailable"
	}
	dst, ok := b.endpointFor(ref)
	if !ok {
		return hopUnknown, "backend pod labels could not be resolved"
	}
	if !b.npIdx.IsIsolated(dst, networkpolicy.Ingress) {
		return hopAllowed, "no NetworkPolicy isolates the backend for ingress; every source is admitted"
	}
	controllers := b.controllerEndpoints()
	if len(controllers) == 0 {
		return hopUnknown, "backend is ingress-isolated by NetworkPolicy and the ingress controller is not identified (BuildOptions.IngressControllers)"
	}

	ports := b.servicePorts(svc, ref)
	var allowed, denied int
	for _, spec := range ports {
		if spec == nil {
			continue // target port could not be resolved: neither allowed nor denied
		}
		switch b.portVerdict(controllers, dst, spec) {
		case networkpolicy.Allowed:
			allowed++
		case networkpolicy.Denied:
			denied++
		}
	}
	switch {
	case len(ports) == 0:
		return hopUnknown, "Service declares no ports"
	case allowed == len(ports):
		return hopAllowed, "NetworkPolicy admits the ingress controller on every Service target port"
	case denied == len(ports) && !b.controllersPartial:
		return hopDenied, "NetworkPolicy denies the ingress controller on every Service target port"
	default:
		return hopUnknown, "NetworkPolicy verdict for the ingress controller is unknown or differs between Service target ports"
	}
}

// portVerdict is Allowed if any controller reaches dst on spec, Unknown if none
// does but at least one verdict is unknown, and Denied otherwise.
func (b *builder) portVerdict(controllers []networkpolicy.Endpoint, dst networkpolicy.Endpoint, spec *networkpolicy.PortSpec) networkpolicy.Verdict {
	verdict := networkpolicy.Denied
	for _, src := range controllers {
		v, _, _ := b.npIdx.Reaches(src, dst, spec)
		switch v {
		case networkpolicy.Allowed:
			return networkpolicy.Allowed
		case networkpolicy.Unknown:
			verdict = networkpolicy.Unknown
		}
	}
	return verdict
}

// servicePorts resolves each Service port to the pod port traffic arrives on.
// An entry is nil when the target port is a name that cannot be resolved from
// the backend's container spec.
func (b *builder) servicePorts(svc *corev1.Service, ref WorkloadRef) []*networkpolicy.PortSpec {
	out := make([]*networkpolicy.PortSpec, 0, len(svc.Spec.Ports))
	for _, sp := range svc.Spec.Ports {
		proto := sp.Protocol
		if proto == "" {
			proto = corev1.ProtocolTCP
		}
		var port int32
		switch tp := sp.TargetPort; {
		case tp.Type == intstr.String && tp.StrVal != "":
			port, _ = b.namedContainerPort(ref, tp.StrVal, proto)
		case tp.Type == intstr.Int && tp.IntVal > 0:
			port = tp.IntVal
		default:
			port = sp.Port // targetPort defaults to port
		}
		if port <= 0 {
			out = append(out, nil)
			continue
		}
		out = append(out, &networkpolicy.PortSpec{Protocol: proto, Port: port})
	}
	return out
}

// namedContainerPort resolves a named targetPort from the backend's pod spec.
func (b *builder) namedContainerPort(ref WorkloadRef, name string, proto corev1.Protocol) (int32, bool) {
	obj := b.workloadObjs[ref]
	if obj == nil {
		return 0, false
	}
	raw, found, err := unstructured.NestedFieldNoCopy(obj, workloadinterface.PodSpec(ref.Kind)...)
	spec, isMap := raw.(map[string]any)
	if err != nil || !found || !isMap {
		return 0, false
	}
	containers, _ := containersOf(spec, "containers", "initContainers")
	for _, c := range containers {
		ports, _ := c["ports"].([]any)
		for _, item := range ports {
			p, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if n, _ := p["name"].(string); n != name {
				continue
			}
			pp := corev1.ProtocolTCP
			if s, _ := p["protocol"].(string); s != "" {
				pp = corev1.Protocol(s)
			}
			if pp != proto {
				continue
			}
			if v, ok := int32FromAny(p["containerPort"]); ok && v > 0 {
				return v, true
			}
		}
	}
	return 0, false
}

func int32FromAny(v any) (int32, bool) {
	switch n := v.(type) {
	case int:
		return int32(n), true //nolint:gosec // port numbers are validated by the API server
	case int32:
		return n, true
	case int64:
		return int32(n), true //nolint:gosec // port numbers are validated by the API server
	case float64:
		return int32(n), true
	}
	return 0, false
}

// endpointFor resolves a workload to its NetworkPolicy endpoint, resolving all
// collected workloads once.
func (b *builder) endpointFor(ref WorkloadRef) (networkpolicy.Endpoint, bool) {
	if b.endpoints == nil {
		refs := slices.Collect(maps.Keys(b.workloadObjs))
		b.endpoints = make(map[WorkloadRef]WorkloadEndpointResult, len(refs))
		for _, r := range ResolveEndpointsFromResources(b.resources, refs) {
			b.endpoints[r.Ref] = r
		}
	}
	r, ok := b.endpoints[ref]
	return r.Endpoint, ok && r.Resolved
}

// controllerEndpoints resolves BuildOptions.IngressControllers once. A
// controller that cannot be resolved is warned about and makes a denial
// unprovable (controllersPartial).
func (b *builder) controllerEndpoints() []networkpolicy.Endpoint {
	if b.controllersResolved {
		return b.controllers
	}
	b.controllersResolved = true
	if len(b.opts.IngressControllers) == 0 {
		return nil
	}
	for _, res := range ResolveEndpointsFromResources(b.resources, b.opts.IngressControllers) {
		if !res.Resolved {
			b.controllersPartial = true
			b.g.warn(fmt.Sprintf("ingress controller %s %s/%s could not be resolved: %s", res.Ref.Kind, res.Ref.Namespace, res.Ref.Name, res.Reason))
			continue
		}
		b.controllers = append(b.controllers, res.Endpoint)
	}
	return b.controllers
}

// --- Layers 3 and 4: Workload -> ServiceAccount -> ClusterAdmin ---

func (b *builder) addIdentityLayer(clusterAdmin Node) {
	bindings := ResolveServiceAccountBindings(b.resources, ServiceAccountAutomountIndex(b.inp.ServiceAccounts))
	analysed := make(map[NodeID]bool)
	for _, bd := range bindings {
		if bd.Skipped {
			b.g.skip(fmt.Sprintf("%s %s/%s: %s", bd.WorkloadRef.Kind, bd.WorkloadRef.Namespace, bd.WorkloadRef.Name, bd.SkipReason))
			continue
		}
		var certain bool
		switch {
		case bd.TokenMounted:
			certain = true
		case bd.TokenUnknown:
			certain = false // the token may be mounted: keep the edge, flag it
		default:
			continue // token provably not mounted: no runs-as edge (proposal §7)
		}

		wNode := b.workloadNode(bd.WorkloadRef)
		saNode := Node{
			ID:        nodeID(NodeServiceAccount, bd.Namespace, bd.ServiceAccountName),
			Kind:      NodeServiceAccount,
			Namespace: bd.Namespace,
			Name:      bd.ServiceAccountName,
		}
		// The workload node is materialised here, not only in the exposure
		// layer, so an internal workload that is not behind any exposed
		// Service is still a valid search source.
		b.g.addNode(wNode)
		b.g.addNode(saNode)

		evidence := "serviceAccountName=" + bd.ServiceAccountName
		if !certain {
			evidence += "; token mount could not be established statically"
		}
		b.g.addEdge(Edge{From: wNode.ID, To: saNode.ID, Kind: EdgeRunsAs, Evidence: evidence, Certain: certain})

		// Escalation is a property of the ServiceAccount, so it is analysed
		// and its edge added once however many workloads share it.
		if !analysed[saNode.ID] {
			analysed[saNode.ID] = true
			b.addEscalationEdge(saNode, clusterAdmin)
		}
	}
}

func (b *builder) addEscalationEdge(sa, clusterAdmin Node) {
	if b.rbacIdx == nil {
		return
	}
	res := b.rbacIdx.AnalyzeEscalation(rbacgraph.Subject{
		Kind:      rbacgraph.KindServiceAccount,
		Namespace: sa.Namespace,
		Name:      sa.Name,
	})
	switch {
	case res.ClusterAdmin:
		b.g.addEdge(Edge{From: sa.ID, To: clusterAdmin.ID, Kind: EdgeEscalates, Evidence: escalationEvidence(res), Certain: true})
	case res.Truncated:
		// Truncated is only meaningful while ClusterAdmin is false: the search
		// ran out of budget, so cluster-admin is not ruled out.
		b.g.addEdge(Edge{
			From: sa.ID, To: clusterAdmin.ID, Kind: EdgeEscalates, Certain: false,
			Evidence: "RBAC escalation search truncated; cluster-admin not ruled out",
		})
	}
}

// escalationEvidence explains how cluster-admin was reached, without assuming
// the result carries any escalation steps.
func escalationEvidence(res rbacgraph.EscalationResult) string {
	for _, u := range res.Unbounded {
		e := u.Edge
		if e.Scope == "" && !e.ScopeUnknown && e.ImpersonatedKind == "" {
			return fmt.Sprintf("%s via %s: %s", u.Subject, e.Primitive, e.Detail)
		}
	}
	if n := len(res.Reached); n > 0 {
		var steps []string
		for _, e := range res.Reached[n-1].Edges {
			steps = append(steps, string(e.Primitive)+": "+e.Detail)
		}
		if len(steps) > 0 {
			return "RBAC escalation: " + strings.Join(steps, " -> ")
		}
	}
	return "bound to cluster-admin-equivalent rules (directly or via granted rules)"
}

// --- helpers ---

// workloadNode builds the node for a workload, with its CVEs attached.
func (b *builder) workloadNode(ref WorkloadRef) Node {
	n := Node{
		ID:           workloadNodeID(ref),
		Kind:         NodeWorkload,
		Namespace:    ref.Namespace,
		Name:         ref.Name,
		WorkloadKind: ref.Kind,
	}
	if b.opts.VulnsByWorkload != nil {
		key := vulnexposure.Workload{Namespace: ref.Namespace, Kind: ref.Kind, Name: ref.Name}
		n.Vulnerabilities = collectVulnerabilities(b.opts.VulnsByWorkload[key], b.opts.MinCVESeverity)
	}
	return n
}

// collectVulnerabilities keeps the CVEs at or above min, one entry per CVE ID
// (highest severity, fix available if any copy has one), sorted by severity
// descending then ID.
func collectVulnerabilities(vulns []storagev1beta1.Vulnerability, minSeverity vulnexposure.Severity) []Vulnerability {
	byID := make(map[string]Vulnerability)
	for _, v := range vulns {
		sev := vulnexposure.ParseSeverity(v.Severity)
		if sev < minSeverity {
			continue
		}
		fix := vulnexposure.FixAvailable(v)
		if cur, seen := byID[v.ID]; seen {
			sev = max(sev, vulnexposure.ParseSeverity(cur.Severity))
			fix = fix || cur.FixAvailable
		}
		byID[v.ID] = Vulnerability{ID: v.ID, Severity: sev.String(), FixAvailable: fix}
	}
	out := slices.Collect(maps.Values(byID))
	slices.SortFunc(out, func(a, c Vulnerability) int {
		if r := cmp.Compare(vulnexposure.ParseSeverity(c.Severity), vulnexposure.ParseSeverity(a.Severity)); r != 0 {
			return r
		}
		return cmp.Compare(a.ID, c.ID)
	})
	return out
}

// indexWorkloadObjects maps each supported workload to its collected object.
// For duplicate identities the lowest resource ID wins; conflicting duplicates
// are already unresolved in ResolveEndpointsFromResources.
func indexWorkloadObjects(resources map[string]workloadinterface.IMetadata) map[WorkloadRef]map[string]any {
	out := make(map[WorkloadRef]map[string]any)
	for _, id := range slices.Sorted(maps.Keys(resources)) {
		r := resources[id]
		if !isSupportedWorkloadResource(r) {
			continue
		}
		ref := WorkloadRef{Namespace: r.GetNamespace(), Kind: r.GetKind(), Name: r.GetName()}
		if _, dup := out[ref]; !dup {
			out[ref] = r.GetObject()
		}
	}
	return out
}
