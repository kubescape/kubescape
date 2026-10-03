package attackpath

import "sort"

// SearchOptions controls path search behaviour.
type SearchOptions struct {
	// From is the source node to start from. Defaults to the Internet node.
	From NodeID
	// To is the sink node to search for. Defaults to ClusterAdmin.
	To NodeID
	// MaxDepth is the maximum number of edges in a path. Defaults to 10.
	MaxDepth int
	// MaxPaths caps the total number of paths returned. Defaults to 100.
	// When the cap is hit, the Truncated flag on the result is set.
	MaxPaths int
}

// SearchResult is the output of FindPaths.
type SearchResult struct {
	Paths []AttackPath
	// Truncated is true when MaxPaths was hit before all paths were found.
	Truncated bool
	// UncertainEdgeCount is the total number of Certain=false edges across
	// all returned paths, surfaced so a "no paths found" result can be
	// accompanied by "but N uncertain edges exist" per proposal §7.
	UncertainEdgeCount int
}

// FindPaths performs a bounded, deterministic depth-first search from
// opts.From to opts.To, returning all simple paths (no repeated nodes)
// up to opts.MaxDepth edges long and opts.MaxPaths total.
// Results are sorted by descending Score so the highest-risk path is first.
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

	var result SearchResult
	visited := make(map[NodeID]bool)
	var currentNodes []Node
	var currentEdges []Edge

	var dfs func(current NodeID)
	dfs = func(current NodeID) {
		if result.Truncated {
			return
		}
		if current == opts.To {
			path := buildPath(g, currentNodes, currentEdges)
			result.Paths = append(result.Paths, path)
			if len(result.Paths) >= opts.MaxPaths {
				result.Truncated = true
			}
			return
		}
		if len(currentEdges) >= opts.MaxDepth {
			return
		}

		// Sort neighbours by To node ID for determinism.
		neighbours := make([]Edge, len(g.Edges[current]))
		copy(neighbours, g.Edges[current])
		sort.Slice(neighbours, func(i, j int) bool {
			return neighbours[i].To < neighbours[j].To
		})

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

	startNode, ok := g.Nodes[opts.From]
	if !ok {
		return result // source does not exist in graph
	}
	visited[opts.From] = true
	currentNodes = append(currentNodes, startNode)
	dfs(opts.From)

	// Score and sort: highest score first.
	for i := range result.Paths {
		result.Paths[i].Score = ScorePath(result.Paths[i])
	}
	sort.Slice(result.Paths, func(i, j int) bool {
		return result.Paths[i].Score > result.Paths[j].Score
	})

	// Count uncertain edges across all paths.
	for _, p := range result.Paths {
		for _, e := range p.Edges {
			if !e.Certain {
				result.UncertainEdgeCount++
			}
		}
	}

	return result
}

// buildPath assembles one AttackPath from the DFS node/edge stacks.
func buildPath(g *Graph, nodes []Node, edges []Edge) AttackPath {
	p := AttackPath{
		Nodes: make([]Node, len(nodes)),
		Edges: make([]Edge, len(edges)),
	}
	copy(p.Nodes, nodes)
	copy(p.Edges, edges)

	certain := true
	maxSev := ""
	for _, e := range p.Edges {
		if !e.Certain {
			certain = false
		}
	}
	for _, n := range p.Nodes {
		if n.Kind == NodeCVE {
			// CVE node Name is the CVE ID; severity is in the incoming edge Evidence.
			for _, e := range p.Edges {
				if e.To == n.ID && e.Kind == EdgeVulnerable {
					// Evidence format: "severity=Critical fix=true"
					sev := extractSeverity(e.Evidence)
					if CVESeverityRank(sev) > CVESeverityRank(maxSev) {
						maxSev = sev
					}
				}
			}
		}
	}
	p.Certain = certain
	p.CVESeverity = maxSev
	return p
}

// extractSeverity parses the severity from an EdgeVulnerable Evidence string.
func extractSeverity(evidence string) string {
	// Evidence format: "severity=Critical fix=true"
	const prefix = "severity="
	start := 0
	for i := 0; i < len(evidence)-len(prefix); i++ {
		if evidence[i:i+len(prefix)] == prefix {
			start = i + len(prefix)
			break
		}
	}
	if start == 0 {
		return ""
	}
	end := start
	for end < len(evidence) && evidence[end] != ' ' {
		end++
	}
	return evidence[start:end]
}
