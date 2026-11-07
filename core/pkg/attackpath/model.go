package attackpath

import (
	"slices"
	"strings"
)

// NodeKind identifies what kind of node sits in the attack graph.
type NodeKind string

const (
	NodeInternet       NodeKind = "Internet"
	NodeService        NodeKind = "Service"
	NodeWorkload       NodeKind = "Workload"
	NodeServiceAccount NodeKind = "ServiceAccount"
	NodeClusterAdmin   NodeKind = "ClusterAdmin"
)

// NodeID is a unique string key for a node.
//
//	Internet:                 "Internet:"
//	Service:                  "Service:prod/web"
//	Workload (kind included): "Workload:prod/Deployment/web"
//	ServiceAccount:           "ServiceAccount:prod/web-sa"
//
// A workload ID carries its Kubernetes kind because a Deployment and a Job
// may share a namespace and name; they run as different ServiceAccounts and
// must never collapse into one node.
type NodeID string

// Vulnerability is one CVE found on a workload. Phase 2 attaches CVEs to the
// workload node instead of modelling them as graph nodes: a CVE is not a hop
// an attacker traverses on the way to a sink, it is a property of the
// workload they land on, so a terminal CVE node would never be on a path to
// cluster-admin and could not influence its score.
type Vulnerability struct {
	ID string
	// Severity is the normalised severity name (Critical, High, Medium, ...).
	Severity     string
	FixAvailable bool
}

// Node is one vertex in the attack graph.
type Node struct {
	ID        NodeID
	Kind      NodeKind
	Namespace string
	Name      string
	// WorkloadKind is the Kubernetes kind (Deployment, Job, ...). Set only
	// when Kind == NodeWorkload.
	WorkloadKind string
	// Vulnerabilities are the CVEs at or above the build's minimum severity,
	// sorted by severity (highest first) then ID. Set only when
	// Kind == NodeWorkload and vulnerability data was supplied.
	Vulnerabilities []Vulnerability
}

// EdgeKind identifies what relationship an edge represents.
type EdgeKind string

const (
	EdgeExposes      EdgeKind = "exposes"       // Internet → Service
	EdgeNetworkReach EdgeKind = "network-reach" // Service → Workload
	EdgeRunsAs       EdgeKind = "runs-as"       // Workload → ServiceAccount
	EdgeEscalates    EdgeKind = "escalates"     // ServiceAccount → ClusterAdmin
)

// Edge is one directed connection between two nodes.
type Edge struct {
	From NodeID
	To   NodeID
	Kind EdgeKind
	// Evidence names the object(s) responsible: Ingress name, policy name,
	// RBAC binding, etc. Parallel edges with the same endpoints, kind and
	// certainty are merged and their evidence is joined with "; ".
	Evidence string
	// Certain is false when the source engine returned Unknown, unclear,
	// or Truncated for this hop. A path containing any Certain=false
	// edge is itself uncertain and must never be silently promoted.
	Certain bool
}

// AttackPath is one end-to-end chain from a source node to a sink node.
type AttackPath struct {
	Nodes []Node
	Edges []Edge
	Score float64
	// Certain is false when any edge in this path has Certain=false.
	Certain bool
	// CVESeverity is the highest CVE severity on any workload node in this
	// path. Empty when no workload on the path has a CVE.
	CVESeverity string
	// CVEFixAvailable is true when any CVE on a workload node in this path
	// has a fix available.
	CVEFixAvailable bool
}

// Graph holds the full directed attack graph for one resource snapshot.
type Graph struct {
	Nodes map[NodeID]Node
	// Edges is indexed by the From node for fast neighbour lookup.
	Edges map[NodeID][]Edge

	// Warnings lists every way the analysis is incomplete: an engine that was
	// unavailable or ambiguous, decode errors, an RBAC search that ran out of
	// budget. When non-empty, "no path found" must not be read as "safe".
	// Sorted and de-duplicated.
	Warnings []string
	// Skipped lists individual objects that were left out rather than guessed
	// at (a workload with no resolvable ServiceAccount, a selector-less
	// exposed Service, a backend with conflicting labels). Sorted and
	// de-duplicated. Unlike Warnings these do not make the analysis
	// incomplete on their own: a static mirror Pod has no identity to resolve.
	Skipped []string
	// HasVulnerabilityData is true when CVE data was supplied to BuildGraph.
	// When false, paths carry no CVE factor and score lower by construction.
	HasVulnerabilityData bool
}

// newGraph allocates an empty Graph.
func newGraph() *Graph {
	return &Graph{
		Nodes: make(map[NodeID]Node),
		Edges: make(map[NodeID][]Edge),
	}
}

func (g *Graph) addNode(n Node) {
	g.Nodes[n.ID] = n
}

// addEdge adds e, merging it into an existing edge with the same endpoints,
// kind and certainty. Merging keeps one edge per (From, To, Kind, Certain)
// so N workloads sharing a ServiceAccount, or N hosts on one Ingress, do not
// consume MaxPaths with paths that differ in nothing a reader can act on.
// Evidence of merged edges is sorted, so the result does not depend on the
// order edges were added in.
func (g *Graph) addEdge(e Edge) {
	edges := g.Edges[e.From]
	for i := range edges {
		x := &edges[i]
		if x.To == e.To && x.Kind == e.Kind && x.Certain == e.Certain {
			x.Evidence = mergeEvidence(x.Evidence, e.Evidence)
			return
		}
	}
	g.Edges[e.From] = append(edges, e)
}

func mergeEvidence(a, b string) string {
	if a == b || b == "" {
		return a
	}
	if a == "" {
		return b
	}
	parts := append(strings.Split(a, "; "), strings.Split(b, "; ")...)
	slices.Sort(parts)
	return strings.Join(slices.Compact(parts), "; ")
}

func (g *Graph) warn(msg string) { g.Warnings = append(g.Warnings, msg) }
func (g *Graph) skip(msg string) { g.Skipped = append(g.Skipped, msg) }

// finalize sorts and de-duplicates the diagnostics so output is
// byte-identical across runs.
func (g *Graph) finalize() {
	slices.Sort(g.Warnings)
	g.Warnings = slices.Compact(g.Warnings)
	slices.Sort(g.Skipped)
	g.Skipped = slices.Compact(g.Skipped)
}

// nodeID builds a canonical NodeID from kind + namespace + name.
func nodeID(kind NodeKind, namespace, name string) NodeID {
	if namespace == "" {
		return NodeID(string(kind) + ":" + name)
	}
	return NodeID(string(kind) + ":" + namespace + "/" + name)
}

// workloadNodeID builds the NodeID of a workload. The Kubernetes kind is part
// of the identity.
func workloadNodeID(ref WorkloadRef) NodeID {
	return NodeID(string(NodeWorkload) + ":" + ref.Namespace + "/" + ref.Kind + "/" + ref.Name)
}
