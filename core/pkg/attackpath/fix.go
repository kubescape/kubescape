package attackpath

import "sort"

// FixSuggestion is the highest-leverage fix for reducing attack paths:
// the single object (node) whose removal from the graph breaks the most paths.
type FixSuggestion struct {
	// Node is the graph node whose removal breaks the most paths.
	Node Node
	// PathsBlocked is how many paths this node appears on.
	PathsBlocked int
	// FingerprintsBlocked lists the fingerprints of every path this
	// node appears on, sorted for determinism.
	FingerprintsBlocked []Fingerprint
}

// SuggestFix returns the single node whose removal from the graph would
// break the most attack paths. It considers only non-terminal, non-source
// nodes (not Internet or ClusterAdmin) since removing those is not
// actionable. When multiple nodes tie, the one with the lexicographically
// smallest NodeID is returned for determinism.
//
// If result has no paths, SuggestFix returns a zero-value FixSuggestion.
func SuggestFix(result SearchResult) FixSuggestion {
	if len(result.Paths) == 0 {
		return FixSuggestion{}
	}

	// Count how many paths each non-terminal, non-source node appears on.
	type nodeCount struct {
		node  Node
		count int
		fps   []Fingerprint
	}
	counts := make(map[NodeID]*nodeCount)

	for _, p := range result.Paths {
		fp := FingerprintPath(p)
		for _, n := range p.Nodes {
			if n.Kind == NodeInternet || n.Kind == NodeClusterAdmin {
				continue // not actionable
			}
			if _, ok := counts[n.ID]; !ok {
				counts[n.ID] = &nodeCount{node: n}
			}
			counts[n.ID].count++
			counts[n.ID].fps = append(counts[n.ID].fps, fp)
		}
	}

	if len(counts) == 0 {
		return FixSuggestion{}
	}

	// Find the node with the highest count, breaking ties by NodeID.
	var best *nodeCount
	for _, nc := range counts {
		if best == nil ||
			nc.count > best.count ||
			(nc.count == best.count && nc.node.ID < best.node.ID) {
			best = nc
		}
	}

	// Sort fingerprints for determinism.
	sort.Slice(best.fps, func(i, j int) bool {
		return best.fps[i] < best.fps[j]
	})

	return FixSuggestion{
		Node:                best.node,
		PathsBlocked:        best.count,
		FingerprintsBlocked: best.fps,
	}
}

// TopFixes returns up to n FixSuggestions ranked by PathsBlocked descending,
// with ties broken by NodeID for determinism. This lets an operator see not
// just the single best fix but a ranked list of the most impactful changes.
func TopFixes(result SearchResult, n int) []FixSuggestion {
	if len(result.Paths) == 0 || n <= 0 {
		return nil
	}

	type nodeCount struct {
		node  Node
		count int
		fps   []Fingerprint
	}
	counts := make(map[NodeID]*nodeCount)

	for _, p := range result.Paths {
		fp := FingerprintPath(p)
		for _, nd := range p.Nodes {
			if nd.Kind == NodeInternet || nd.Kind == NodeClusterAdmin {
				continue
			}
			if _, ok := counts[nd.ID]; !ok {
				counts[nd.ID] = &nodeCount{node: nd}
			}
			counts[nd.ID].count++
			counts[nd.ID].fps = append(counts[nd.ID].fps, fp)
		}
	}

	all := make([]*nodeCount, 0, len(counts))
	for _, nc := range counts {
		sort.Slice(nc.fps, func(i, j int) bool { return nc.fps[i] < nc.fps[j] })
		all = append(all, nc)
	}

	// Sort: highest count first, then NodeID for ties.
	sort.Slice(all, func(i, j int) bool {
		if all[i].count != all[j].count {
			return all[i].count > all[j].count
		}
		return all[i].node.ID < all[j].node.ID
	})

	if n > len(all) {
		n = len(all)
	}
	out := make([]FixSuggestion, n)
	for i := 0; i < n; i++ {
		out[i] = FixSuggestion{
			Node:                all[i].node,
			PathsBlocked:        all[i].count,
			FingerprintsBlocked: all[i].fps,
		}
	}
	return out
}
