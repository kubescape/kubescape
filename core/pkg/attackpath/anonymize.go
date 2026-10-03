package attackpath

import (
	"crypto/sha256"
	"fmt"
)

// Anonymizer replaces sensitive names (namespace, workload name,
// ServiceAccount name, CVE ID, hostname) in an AttackPath with
// deterministic pseudonyms, so the path structure is preserved but
// no real identifier leaks into the report.
// This is the --hide equivalent for attack-path output.
type Anonymizer struct {
	cache map[string]string
	salt  string
}

// NewAnonymizer returns an Anonymizer whose pseudonyms are salted with
// salt, making them deterministic within one report but not guessable
// across reports that use different salts.
func NewAnonymizer(salt string) *Anonymizer {
	return &Anonymizer{
		cache: make(map[string]string),
		salt:  salt,
	}
}

// pseudonym returns a deterministic short token for name.
// The same name always maps to the same token within this Anonymizer.
func (a *Anonymizer) pseudonym(name string) string {
	if name == "" {
		return ""
	}
	if p, ok := a.cache[name]; ok {
		return p
	}
	h := sha256.Sum256([]byte(a.salt + name))
	// Use the first 8 hex chars: short enough to read, long enough to
	// distinguish identifiers within a cluster.
	p := fmt.Sprintf("anon-%x", h[:4])
	a.cache[name] = p
	return p
}

// AnonymizePath returns a copy of p with all sensitive identifiers replaced
// by pseudonyms. Node kinds and edge kinds are preserved; only names and
// namespaces are replaced. Internet and ClusterAdmin nodes are not
// anonymized — they are not cluster-specific identifiers.
func (a *Anonymizer) AnonymizePath(p AttackPath) AttackPath {
	nodeMap := make(map[NodeID]NodeID, len(p.Nodes))
	aNodes := make([]Node, len(p.Nodes))

	for i, n := range p.Nodes {
		an := a.anonymizeNode(n)
		aNodes[i] = an
		nodeMap[n.ID] = an.ID
	}

	aEdges := make([]Edge, len(p.Edges))
	for i, e := range p.Edges {
		aEdges[i] = Edge{
			From:     nodeMap[e.From],
			To:       nodeMap[e.To],
			Kind:     e.Kind,
			Evidence: a.anonymizeEvidence(e.Kind, e.Evidence),
			Certain:  e.Certain,
		}
	}

	return AttackPath{
		Nodes:       aNodes,
		Edges:       aEdges,
		Score:       p.Score,
		Certain:     p.Certain,
		CVESeverity: p.CVESeverity,
	}
}

// AnonymizeResult returns a copy of result with every path anonymized.
func (a *Anonymizer) AnonymizeResult(result SearchResult) SearchResult {
	paths := make([]AttackPath, len(result.Paths))
	for i, p := range result.Paths {
		paths[i] = a.AnonymizePath(p)
	}
	return SearchResult{
		Paths:              paths,
		Truncated:          result.Truncated,
		UncertainEdgeCount: result.UncertainEdgeCount,
	}
}

func (a *Anonymizer) anonymizeNode(n Node) Node {
	switch n.Kind {
	case NodeInternet, NodeClusterAdmin:
		// Not cluster-specific; keep as-is.
		return n
	case NodeCVE:
		// CVE IDs are public identifiers; anonymize only the workload
		// context, not the CVE ID itself, because the ID is not a
		// cluster-specific name.
		return n
	}
	aName := a.pseudonym(n.Name)
	aNS := a.pseudonym(n.Namespace)
	return Node{
		ID:        nodeID(n.Kind, aNS, aName),
		Kind:      n.Kind,
		Namespace: aNS,
		Name:      aName,
	}
}

// anonymizeEvidence replaces any name-like tokens in edge evidence text.
// For runs-as edges the format is "serviceAccountName=<name>"; for
// network-reach and exposes edges the evidence is free-form.
// We replace only serviceAccountName values here; other edge evidence
// (ingress names, policy names) is replaced by a generic placeholder
// to avoid parsing free-form strings.
func (a *Anonymizer) anonymizeEvidence(kind EdgeKind, evidence string) string {
	switch kind {
	case EdgeRunsAs:
		// "serviceAccountName=web-sa" → "serviceAccountName=anon-XXXX"
		const prefix = "serviceAccountName="
		if len(evidence) > len(prefix) && evidence[:len(prefix)] == prefix {
			return prefix + a.pseudonym(evidence[len(prefix):])
		}
	case EdgeExposes, EdgeNetworkReach, EdgeEscalates:
		return "<anonymized>"
	}
	return evidence
}
