// Package k8scveindex builds a component applicability index from the
// official Kubernetes CVE feed. Vulnerability databases record Kubernetes
// CVEs against the k8s.io/kubernetes module, which does not say whether the
// API server, the kubelet or another component is affected; the feed does.
package k8scveindex

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

type Applicability int

const (
	// Unattributed means the feed has no entry for the CVE, or one that could
	// not be parsed, so the CVE cannot be tied to a component.
	Unattributed Applicability = iota
	Applicable
	NotApplicable
)

func (a Applicability) String() string {
	switch a {
	case Applicable:
		return "applicable"
	case NotApplicable:
		return "not-applicable"
	default:
		return "unattributed"
	}
}

type entry struct {
	affected    map[string][]versionRange
	windowsOnly bool
}

type Index struct {
	// Updated is when the feed was last refreshed upstream.
	Updated time.Time
	entries map[string]*entry
}

type feed struct {
	Meta struct {
		UpdatedAt time.Time `json:"updated_at"`
	} `json:"_kubernetes_io"`
	Items []struct {
		ID          string `json:"id"`
		Summary     string `json:"summary"`
		ContentText string `json:"content_text"`
	} `json:"items"`
}

var windowsPlatform = regexp.MustCompile(`(?i)\bwindows\b`)

// Parse builds an index from the feed's JSON. Entries whose affected versions
// cannot be parsed are kept, so Lookup reports them as unattributed rather
// than as unknown.
func Parse(r io.Reader) (*Index, error) {
	var f feed
	if err := json.NewDecoder(r).Decode(&f); err != nil {
		return nil, fmt.Errorf("decode kubernetes cve feed: %w", err)
	}
	if f.Meta.UpdatedAt.IsZero() || len(f.Items) == 0 {
		return nil, fmt.Errorf("kubernetes cve feed is empty or has no update time")
	}

	ix := &Index{Updated: f.Meta.UpdatedAt, entries: make(map[string]*entry, len(f.Items))}
	for _, item := range f.Items {
		e := &entry{windowsOnly: windowsPlatform.MatchString(item.Summary)}
		if lines, ok := affectedSection(item.ContentText); ok {
			e.affected, _ = parseAffected(lines)
		}
		ix.entries[strings.ToUpper(item.ID)] = e
	}
	return ix, nil
}

// Lookup reports whether cve affects component at version on a node running
// operatingSystem (as in Node status.nodeInfo.operatingSystem).
func (ix *Index) Lookup(cve, component, version, operatingSystem string) Applicability {
	e, ok := ix.entries[strings.ToUpper(cve)]
	if !ok || e.affected == nil {
		return Unattributed
	}
	v, full, err := parseVersion(version)
	if err != nil || !full {
		return Unattributed
	}
	if e.windowsOnly && !strings.EqualFold(operatingSystem, "windows") {
		return NotApplicable
	}
	for _, r := range e.affected[component] {
		if r.contains(v) {
			return Applicable
		}
	}
	return NotApplicable
}

// Stale reports whether the index is older than maxAge or than the
// vulnerability DB it is used with. A zero maxAge or dbBuilt is ignored.
func (ix *Index) Stale(now time.Time, maxAge time.Duration, dbBuilt time.Time) bool {
	if maxAge > 0 && now.Sub(ix.Updated) > maxAge {
		return true
	}
	return !dbBuilt.IsZero() && ix.Updated.Before(dbBuilt)
}
