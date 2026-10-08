package attackpath

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
)

// Fingerprint is a stable, order-independent identifier for one AttackPath.
// It is built from the sorted node kinds and names in the path so that:
//   - The same logical path produces the same fingerprint across runs
//     (determinism requirement from proposal §7).
//   - Renaming an unrelated workload does not change the fingerprint of
//     a path that does not involve it.
//   - Two paths that differ only in edge evidence (e.g. which Ingress
//     exposes the Service) get different fingerprints because the node
//     set differs.
//
// The fingerprint is used as the key for exception matching: an operator
// who accepts the risk of a specific path adds its fingerprint to the
// exceptions file and that path is suppressed in future runs.
type Fingerprint string

// FingerprintPath computes a stable Fingerprint for p.
// Algorithm: sort the node IDs, join with "|", SHA-256, take first 16 hex chars.
func FingerprintPath(p AttackPath) Fingerprint {
	ids := make([]string, len(p.Nodes))
	for i, n := range p.Nodes {
		ids[i] = string(n.ID)
	}
	sort.Strings(ids)
	raw := strings.Join(ids, "|")
	h := sha256.Sum256([]byte(raw))
	return Fingerprint(fmt.Sprintf("%x", h[:8]))
}

// FingerprintResult returns the fingerprint for every path in result,
// in the same order as result.Paths.
func FingerprintResult(result SearchResult) []Fingerprint {
	fps := make([]Fingerprint, len(result.Paths))
	for i, p := range result.Paths {
		fps[i] = FingerprintPath(p)
	}
	return fps
}
