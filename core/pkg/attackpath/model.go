package attackpath

import "github.com/kubescape/kubescape/v4/core/pkg/vulnexposure"

// NodeKind identifies what kind of node sits in the attack graph.
type NodeKind string

const (
	NodeInternet       NodeKind = "Internet"
	NodeService        NodeKind = "Service"
	NodeWorkload       NodeKind = "Workload"
	NodeServiceAccount NodeKind = "ServiceAccount"
	NodeClusterAdmin   NodeKind = "ClusterAdmin"
	NodeCVE            NodeKind = "CVE"
)

// NodeID is a unique string key for a node: kind:namespace/name
// e.g. "Workload:prod/web", "ServiceAccount:prod/web-sa", "Internet:"
type NodeID string

// Node is one vertex in the attack graph.
type Node struct {
	ID        NodeID
	Kind      NodeKind
	Namespace string
	Name      string
}

// EdgeKind identifies what relationship an edge represents.
type EdgeKind string

const (
	EdgeExposes      EdgeKind = "exposes"       // Internet → Service
	EdgeNetworkReach EdgeKind = "network-reach" // Service → Workload
	EdgeRunsAs       EdgeKind = "runs-as"       // Workload → ServiceAccount
	EdgeEscalates    EdgeKind = "escalates"     // ServiceAccount → ClusterAdmin
	EdgeVulnerable   EdgeKind = "vulnerable"    // Workload → CVE
)

// Edge is one directed connection between two nodes.
type Edge struct {
	From NodeID
	To   NodeID
	Kind EdgeKind
	// Evidence names the object responsible: Ingress name, policy name,
	// RBAC binding, CVE ID, etc.
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
	// CVESeverity is the maximum CVE severity found on any CVE node in
	// this path. Empty when no CVE node is present.
	CVESeverity string
}

// Graph holds the full directed attack graph for one resource snapshot.
type Graph struct {
	Nodes map[NodeID]Node
	// Edges is indexed by the From node for fast neighbour lookup.
	Edges map[NodeID][]Edge
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

func (g *Graph) addEdge(e Edge) {
	g.Edges[e.From] = append(g.Edges[e.From], e)
}

// nodeID builds a canonical NodeID from kind + namespace + name.
func nodeID(kind NodeKind, namespace, name string) NodeID {
	if namespace == "" {
		return NodeID(string(kind) + ":" + name)
	}
	return NodeID(string(kind) + ":" + namespace + "/" + name)
}

// CVESeverityRank maps a severity string to an int for scoring.
// Mirrors vulnexposure.ParseSeverity ordering without importing that package
// into model.go directly.
func CVESeverityRank(severity string) int {
	return int(vulnexposure.ParseSeverity(severity))
}
