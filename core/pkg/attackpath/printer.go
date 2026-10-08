package attackpath

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/kubescape/kubescape/v4/core/pkg/vulnexposure"
)

// Format is a supported output format for attack-path results.
type Format string

const (
	FormatPretty   Format = "pretty"
	FormatJSON     Format = "json"
	FormatSARIF    Format = "sarif"
	FormatMarkdown Format = "markdown"
)

// ParseFormat parses a format string, returning an error for unsupported values.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "pretty", "":
		return FormatPretty, nil
	case "json":
		return FormatJSON, nil
	case "sarif":
		return FormatSARIF, nil
	case "markdown", "md":
		return FormatMarkdown, nil
	default:
		return "", fmt.Errorf("unsupported format %q: supported values are pretty, json, sarif, markdown", s)
	}
}

// PrintResult writes the SearchResult to w in the requested format.
// It always prints the uncertain-edge and truncated counts at the end so
// a "no paths found" result is never silently treated as "safe" per
// proposal §7.
func PrintResult(w io.Writer, result SearchResult, format Format, warnings []string) error {
	switch format {
	case FormatJSON:
		return printJSON(w, result, warnings)
	case FormatSARIF:
		return printSARIF(w, result, warnings)
	case FormatMarkdown:
		return printMarkdown(w, result, warnings)
	default:
		return printPretty(w, result, warnings)
	}
}

// --- JSON output ---

// jsonOutput is the top-level JSON document shape. Factors are included
// per proposal §9 so the ranking is auditable.
type jsonOutput struct {
	Paths              []jsonPath `json:"paths"`
	TotalPaths         int        `json:"total_paths"`
	Truncated          bool       `json:"truncated"`
	UncertainEdgeCount int        `json:"uncertain_edge_count"`
	Warnings           []string   `json:"warnings,omitempty"`
}

type jsonPath struct {
	Score        float64     `json:"score"`
	Certain      bool        `json:"certain"`
	CVESeverity  string      `json:"cve_severity,omitempty"`
	HopCount     int         `json:"hop_count"`
	Nodes        []jsonNode  `json:"nodes"`
	Edges        []jsonEdge  `json:"edges"`
	ScoreFactors jsonFactors `json:"score_factors"`
}

type jsonNode struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

type jsonEdge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Kind     string `json:"kind"`
	Evidence string `json:"evidence"`
	Certain  bool   `json:"certain"`
}

type jsonFactors struct {
	CVESeverityRank  int     `json:"cve_severity_rank"`
	ClusterAdminSink bool    `json:"cluster_admin_sink"`
	Certain          bool    `json:"certain"`
	HopCountBonus    float64 `json:"hop_count_bonus"`
	FixAvailable     bool    `json:"fix_available"`
}

func printJSON(w io.Writer, result SearchResult, warnings []string) error {
	out := jsonOutput{
		TotalPaths:         len(result.Paths),
		Truncated:          result.Truncated,
		UncertainEdgeCount: result.UncertainEdgeCount,
		Warnings:           warnings,
	}
	for _, p := range result.Paths {
		jp := jsonPath{
			Score:       p.Score,
			Certain:     p.Certain,
			CVESeverity: p.CVESeverity,
			HopCount:    len(p.Edges),
			ScoreFactors: jsonFactors{
				CVESeverityRank:  CVESeverityRank(p.CVESeverity),
				ClusterAdminSink: hasSink(p, NodeClusterAdmin),
				Certain:          p.Certain,
				HopCountBonus:    hopBonus(len(p.Edges)),
				FixAvailable:     hasFixAvailable(p),
			},
		}
		for _, n := range p.Nodes {
			jp.Nodes = append(jp.Nodes, jsonNode{
				Kind:      string(n.Kind),
				Namespace: n.Namespace,
				Name:      n.Name,
			})
		}
		for _, e := range p.Edges {
			jp.Edges = append(jp.Edges, jsonEdge{
				From:     string(e.From),
				To:       string(e.To),
				Kind:     string(e.Kind),
				Evidence: e.Evidence,
				Certain:  e.Certain,
			})
		}
		out.Paths = append(out.Paths, jp)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// --- Pretty output ---

func printPretty(w io.Writer, result SearchResult, warnings []string) error {
	for i, p := range result.Paths {
		certainLabel := "CERTAIN"
		if !p.Certain {
			certainLabel = "UNCERTAIN"
		}
		fmt.Fprintf(w, "PATH #%d  score %.1f  %s\n", i+1, p.Score, certainLabel)
		for j, e := range p.Edges {
			fromNode := nodeFromID(p, e.From)
			toNode := nodeFromID(p, e.To)
			certMark := ""
			if !e.Certain {
				certMark = " [uncertain]"
			}
			indent := strings.Repeat("  ", j)
			fmt.Fprintf(w, "%s  [%s] %s -(%s)-> [%s] %s%s\n",
				indent,
				fromNode.Kind, labelOf(fromNode),
				e.Evidence,
				toNode.Kind, labelOf(toNode),
				certMark,
			)
		}
		if p.CVESeverity != "" {
			fmt.Fprintf(w, "  CVE severity on path: %s\n", p.CVESeverity)
		}
		fmt.Fprintln(w)
	}

	// Always print summary counts so "no paths" is never silent.
	if len(result.Paths) == 0 {
		fmt.Fprintln(w, "No attack paths found from Internet to cluster-admin.")
	} else {
		fmt.Fprintf(w, "%d path(s) found.\n", len(result.Paths))
	}
	if result.Truncated {
		fmt.Fprintln(w, "WARNING: result is truncated — more paths may exist beyond the cap.")
	}
	if result.UncertainEdgeCount > 0 {
		fmt.Fprintf(w, "NOTE: %d uncertain edge(s) in results — treat uncertain paths as potential, not confirmed.\n",
			result.UncertainEdgeCount)
	}
	for _, warn := range warnings {
		fmt.Fprintf(w, "WARN: %s\n", warn)
	}
	return nil
}

// --- helpers ---

func nodeFromID(p AttackPath, id NodeID) Node {
	for _, n := range p.Nodes {
		if n.ID == id {
			return n
		}
	}
	return Node{ID: id, Kind: NodeKind(id)}
}

func labelOf(n Node) string {
	if n.Namespace != "" {
		return n.Namespace + "/" + n.Name
	}
	return n.Name
}

func hasSink(p AttackPath, kind NodeKind) bool {
	for _, n := range p.Nodes {
		if n.Kind == kind {
			return true
		}
	}
	return false
}

func hasFixAvailable(p AttackPath) bool {
	for _, e := range p.Edges {
		if e.Kind == EdgeVulnerable && containsString(e.Evidence, "fix=true") {
			return true
		}
	}
	return false
}

func hopBonus(hops int) float64 {
	switch {
	case hops <= 3:
		return 1
	case hops <= 5:
		return 0.5
	default:
		return 0
	}
}

// CVESeverityFromString parses a severity string for use by the CLI layer,
// so cmd/scan/attackpaths.go does not need to import vulnexposure directly.
func CVESeverityFromString(s string) vulnexposure.Severity {
	sev := vulnexposure.ParseSeverity(s)
	if sev == vulnexposure.SeverityUnknown {
		return vulnexposure.SeverityHigh
	}
	return sev
}
