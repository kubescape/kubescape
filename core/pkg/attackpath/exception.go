package attackpath

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"
)

// Exception records one accepted-risk entry for a specific attack path.
// The file format is a JSON array of Exception objects, stored at the
// path passed to --exceptions on the attack-paths subcommand.
//
// An operator who accepts the risk of a specific path:
//  1. Runs `kubescape scan attack-paths --format json` to get fingerprints.
//  2. Adds an Exception entry for the fingerprint to their exceptions file.
//  3. Future runs with `--exceptions <file>` suppress that path.
type Exception struct {
	// Fingerprint is the stable path ID produced by FingerprintPath.
	Fingerprint Fingerprint `json:"fingerprint"`
	// Reason is a free-text human note explaining why this path is accepted.
	Reason string `json:"reason"`
	// AcceptedBy is the name or email of the person who accepted the risk.
	AcceptedBy string `json:"accepted_by,omitempty"`
	// ExpiresAt is an optional RFC 3339 expiry date. An expired exception
	// is treated as if it were absent: the path reappears in future runs.
	ExpiresAt string `json:"expires_at,omitempty"`
}

// LoadExceptions reads an exceptions file from path and returns the parsed
// entries. A missing file returns an empty slice, not an error, so a scan
// without an exceptions file behaves identically to one with an empty file.
func LoadExceptions(path string) ([]Exception, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading exceptions file %q: %w", path, err)
	}
	var exceptions []Exception
	if err := json.Unmarshal(data, &exceptions); err != nil {
		return nil, fmt.Errorf("parsing exceptions file %q: %w", path, err)
	}
	return exceptions, nil
}

// ActiveExceptions returns only exceptions that have not expired.
// An exception with an empty ExpiresAt never expires.
func ActiveExceptions(exceptions []Exception) []Exception {
	now := time.Now()
	var active []Exception
	for _, e := range exceptions {
		if e.ExpiresAt == "" {
			active = append(active, e)
			continue
		}
		t, err := time.Parse(time.RFC3339, e.ExpiresAt)
		if err != nil {
			// Malformed date: treat as non-expiring and include it,
			// so a typo does not silently suppress the exception.
			active = append(active, e)
			continue
		}
		if now.Before(t) {
			active = append(active, e)
		}
	}
	return active
}

// ExceptionIndex is a fast lookup set built from a slice of active exceptions.
type ExceptionIndex map[Fingerprint]Exception

// NewExceptionIndex builds an ExceptionIndex from active exceptions.
func NewExceptionIndex(exceptions []Exception) ExceptionIndex {
	idx := make(ExceptionIndex, len(exceptions))
	for _, e := range exceptions {
		idx[e.Fingerprint] = e
	}
	return idx
}

// ApplyExceptions filters result, removing any path whose fingerprint
// appears in idx. It returns the filtered result and a separate slice of
// suppressed paths with the matching Exception for each, sorted by
// fingerprint for determinism.
func ApplyExceptions(result SearchResult, idx ExceptionIndex) (filtered SearchResult, suppressed []SuppressedPath) {
	var keptPaths []AttackPath
	for _, p := range result.Paths {
		fp := FingerprintPath(p)
		if exc, ok := idx[fp]; ok {
			suppressed = append(suppressed, SuppressedPath{
				Path:        p,
				Fingerprint: fp,
				Exception:   exc,
			})
			continue
		}
		keptPaths = append(keptPaths, p)
	}

	// Sort suppressed by fingerprint for deterministic output.
	sort.Slice(suppressed, func(i, j int) bool {
		return suppressed[i].Fingerprint < suppressed[j].Fingerprint
	})

	filtered = SearchResult{
		Paths:              keptPaths,
		Truncated:          result.Truncated,
		UncertainEdgeCount: result.UncertainEdgeCount,
	}
	// Recount uncertain edges after filtering.
	filtered.UncertainEdgeCount = 0
	for _, p := range keptPaths {
		for _, e := range p.Edges {
			if !e.Certain {
				filtered.UncertainEdgeCount++
			}
		}
	}
	return filtered, suppressed
}

// SuppressedPath pairs one suppressed AttackPath with the Exception that
// matched it and its fingerprint, for audit output.
type SuppressedPath struct {
	Path        AttackPath
	Fingerprint Fingerprint
	Exception   Exception
}
