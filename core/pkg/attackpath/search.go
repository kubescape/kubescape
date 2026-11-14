package attackpath

import (
	"cmp"
	"slices"
	"strings"

	"github.com/kubescape/kubescape/v4/core/pkg/vulnexposure"
)

// SearchOptions controls path search behaviour.
type SearchOptions struct {
	// From is the source node to start from. Defaults to the Internet node.
	From NodeID
	// To is the sink node to search for. Defaults to ClusterAdmin.
	To NodeID
	// MaxDepth is the maximum number of edges in a path. Defaults to 10.
	MaxDepth int
	// MaxPaths caps the total number of paths returned. Defaults to 100.
	MaxPaths int
}

// SearchResult is the output of FindPaths.
type SearchResult struct {
	Paths []AttackPath
	// Truncated is true only when a path beyond MaxPaths exists: a search that
	// finds exactly MaxPaths paths and nothing more is complete. When true,
	// Paths holds the first MaxPaths paths in deterministic search order, not
	// the MaxPaths highest-scoring ones.
	Truncated bool
	// DepthLimited is true when the search stopped extending at least one
	// path because it reached MaxDepth. Longer paths may exist.
	DepthLimited bool
	// UncertainEdgeCount is the number of distinct Certain=false edges
	// reachable from the source, whether or not they lie on a complete path.
	// It is what lets a "no paths found" result be reported as "but N
	// uncertain edges exist" per proposal §7.
	UncertainEdgeCount int
	// Warnings, Skipped and HasVulnerabilityData are copied from the Graph so
	// a negative result carries its own diagnostics.
	Warnings             []string
	Skipped              []string
	HasVulnerabilityData bool
	// Incomplete is true when the graph was built from incomplete analysis
	// (len(Warnings) > 0). An empty Paths with Incomplete set is not a
	// statement that the cluster is safe.
	Incomplete bool
}

// FindPaths performs a bounded, deterministic depth-first search from
// opts.From to opts.To, returning all simple paths (no repeated nodes)
// up to opts.MaxDepth edges long and opts.MaxPaths total.
// Results are sorted by descending Score, ties broken by path identity, so
// the highest-risk path is first and the order is stable across runs.
func FindPaths(g *Graph, opts SearchOptions) SearchResult {
	if opts.From == "" {
		opts.From = nodeID(NodeInternet, "", "")
	}
	if opts.To == "" {
		opts.To = nodeID(NodeClusterAdmin, "", "cluster-admin")
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 10
	}
	if opts.MaxPaths <= 0 {
		opts.MaxPaths = 100
	}

	result := SearchResult{
		Warnings:             g.Warnings,
		Skipped:              g.Skipped,
		HasVulnerabilityData: g.HasVulnerabilityData,
		Incomplete:           len(g.Warnings) > 0,
	}

	startNode, ok := g.Nodes[opts.From]
	if !ok {
		return result // source does not exist in graph
	}
	result.UncertainEdgeCount = countReachableUncertainEdges(g, opts.From)

	visited := map[NodeID]bool{opts.From: true}
	currentNodes := []Node{startNode}
	var currentEdges []Edge

	var dfs func(current NodeID)
	dfs = func(current NodeID) {
		if result.Truncated {
			return
		}
		if current == opts.To {
			if len(result.Paths) >= opts.MaxPaths {
				result.Truncated = true // a path exists beyond the cap
				return
			}
			result.Paths = append(result.Paths, buildPath(currentNodes, currentEdges))
			return
		}
		neighbours := sortedEdges(g.Edges[current])
		if len(currentEdges) >= opts.MaxDepth {
			for _, e := range neighbours {
				if _, known := g.Nodes[e.To]; known && !visited[e.To] {
					result.DepthLimited = true
					break
				}
			}
			return
		}
		for _, edge := range neighbours {
			if visited[edge.To] {
				continue // no cycles
			}
			nextNode, ok := g.Nodes[edge.To]
			if !ok {
				continue
			}
			visited[edge.To] = true
			currentNodes = append(currentNodes, nextNode)
			currentEdges = append(currentEdges, edge)
			dfs(edge.To)
			// backtrack
			currentNodes = currentNodes[:len(currentNodes)-1]
			currentEdges = currentEdges[:len(currentEdges)-1]
			visited[edge.To] = false
		}
	}
	dfs(opts.From)

	for i := range result.Paths {
		result.Paths[i].Score = ScorePath(result.Paths[i])
	}
	slices.SortStableFunc(result.Paths, func(a, b AttackPath) int {
		if c := cmp.Compare(b.Score, a.Score); c != 0 {
			return c // higher score first
		}
		return strings.Compare(pathKey(a), pathKey(b))
	})
	return result
}

// sortedEdges returns a copy of edges ordered by destination, then kind,
// then certain-before-uncertain, then evidence, so traversal order never
// depends on insertion order.
func sortedEdges(edges []Edge) []Edge {
	out := slices.Clone(edges)
	slices.SortFunc(out, func(a, b Edge) int {
		if c := cmp.Compare(a.To, b.To); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Kind, b.Kind); c != 0 {
			return c
		}
		if a.Certain != b.Certain {
			if a.Certain {
				return -1
			}
			return 1
		}
		return cmp.Compare(a.Evidence, b.Evidence)
	})
	return out
}

// pathKey is a total order over distinct paths, used as the score tie-break.
func pathKey(p AttackPath) string {
	var sb strings.Builder
	for _, e := range p.Edges {
		sb.WriteString(string(e.From))
		sb.WriteString(">")
		sb.WriteString(string(e.To))
		sb.WriteString("/")
		sb.WriteString(string(e.Kind))
		if e.Certain {
			sb.WriteString("/certain/")
		} else {
			sb.WriteString("/uncertain/")
		}
		sb.WriteString(e.Evidence)
		sb.WriteString("|")
	}
	return sb.String()
}

// countReachableUncertainEdges counts distinct Certain=false edges reachable
// from the source, ignoring depth and the sink.
func countReachableUncertainEdges(g *Graph, from NodeID) int {
	seen := map[NodeID]bool{from: true}
	queue := []NodeID{from}
	count := 0
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range g.Edges[cur] {
			if !e.Certain {
				count++
			}
			if !seen[e.To] {
				seen[e.To] = true
				queue = append(queue, e.To)
			}
		}
	}
	return count
}

// buildPath assembles one AttackPath from the DFS node/edge stacks.
func buildPath(nodes []Node, edges []Edge) AttackPath {
	p := AttackPath{
		Nodes:   slices.Clone(nodes),
		Edges:   slices.Clone(edges),
		Certain: true,
	}
	for _, e := range p.Edges {
		if !e.Certain {
			p.Certain = false
		}
	}
	best := vulnexposure.SeverityUnknown
	for _, n := range p.Nodes {
		for _, v := range n.Vulnerabilities {
			if s := vulnexposure.ParseSeverity(v.Severity); s > best {
				best = s
			}
			if v.FixAvailable {
				p.CVEFixAvailable = true
			}
		}
	}
	if best > vulnexposure.SeverityUnknown {
		p.CVESeverity = best.String()
	}
	return p
}
