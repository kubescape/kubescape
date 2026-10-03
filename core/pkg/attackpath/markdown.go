package attackpath

import (
	"fmt"
	"io"
	"strings"
)

// printMarkdown writes a Markdown report of the SearchResult to w.
// The format is a GitHub-flavoured Markdown table of paths followed by
// collapsible detail sections per path.
func printMarkdown(w io.Writer, result SearchResult, warnings []string) error {
	fmt.Fprintln(w, "# Kubescape Attack-Path Report")
	fmt.Fprintln(w)

	if len(result.Paths) == 0 {
		fmt.Fprintln(w, "> ✅ No attack paths found from Internet to cluster-admin.")
	} else {
		fmt.Fprintf(w, "**%d path(s) found.**\n\n", len(result.Paths))

		// Summary table.
		fmt.Fprintln(w, "| # | Score | Certain | CVE Severity | Hops |")
		fmt.Fprintln(w, "|---|-------|---------|-------------|------|")
		for i, p := range result.Paths {
			certain := "✅"
			if !p.Certain {
				certain = "⚠️"
			}
			fmt.Fprintf(w, "| %d | %.1f | %s | %s | %d |\n",
				i+1, p.Score, certain, severityOrDash(p.CVESeverity), len(p.Edges))
		}
		fmt.Fprintln(w)

		// Detail per path.
		for i, p := range result.Paths {
			fmt.Fprintf(w, "## Path #%d — score %.1f\n\n", i+1, p.Score)
			fmt.Fprintln(w, "```")
			for j, e := range p.Edges {
				fromNode := nodeFromID(p, e.From)
				toNode := nodeFromID(p, e.To)
				certMark := ""
				if !e.Certain {
					certMark = " ⚠️ uncertain"
				}
				indent := strings.Repeat("  ", j)
				fmt.Fprintf(w, "%s[%s] %s -(%s)-> [%s] %s%s\n",
					indent,
					fromNode.Kind, labelOf(fromNode),
					e.Evidence,
					toNode.Kind, labelOf(toNode),
					certMark,
				)
			}
			fmt.Fprintln(w, "```")
			fmt.Fprintln(w)
		}
	}

	// Notices section — always printed per proposal §7.
	if result.Truncated || result.UncertainEdgeCount > 0 || len(warnings) > 0 {
		fmt.Fprintln(w, "## Notices")
		fmt.Fprintln(w)
		if result.Truncated {
			fmt.Fprintln(w, "- ⚠️ **Truncated** — more paths may exist beyond the cap.")
		}
		if result.UncertainEdgeCount > 0 {
			fmt.Fprintf(w, "- ℹ️ **%d uncertain edge(s)** — treat uncertain paths as potential, not confirmed.\n",
				result.UncertainEdgeCount)
		}
		for _, warn := range warnings {
			fmt.Fprintf(w, "- ⚠️ %s\n", warn)
		}
	}

	return nil
}

func severityOrDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
