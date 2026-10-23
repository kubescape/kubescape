package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/jwalton/gchalk"
	tableprinterutils "github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"sigs.k8s.io/yaml"
)

// PrintPretty writes a human-readable diff summary to w.
func PrintPretty(w io.Writer, cs *ChangeSet) error {
	for _, warning := range cs.Warnings {
		if _, err := fmt.Fprintf(w, "%s %s\n", gchalk.WithBrightYellow().Bold("WARNING:"), warning); err != nil {
			return err
		}
	}
	if err := printSection(w, "New failures", cs.New, "+"); err != nil {
		return err
	}
	if err := printSection(w, "Resolved", cs.Resolved, "-"); err != nil {
		return err
	}
	if len(cs.Unchanged) > 0 {
		if err := printSection(w, "Still failing (unchanged)", cs.Unchanged, " "); err != nil {
			return err
		}
	}
	if len(cs.Incomparable) > 0 {
		if err := printSection(w, "Incomparable", cs.Incomparable, "?"); err != nil {
			return err
		}
	}

	_, err := fmt.Fprintf(w, "\nSummary: %s new, %s resolved, %s unchanged, %s incomparable\n",
		formatSummaryCount(len(cs.New), "+"),
		formatSummaryCount(len(cs.Resolved), "-"),
		formatSummaryCount(len(cs.Unchanged), " "),
		formatSummaryCount(len(cs.Incomparable), "?"),
	)
	return err
}

func formatSummaryCount(count int, prefix string) string {
	formatted := fmt.Sprintf("%d", count)
	switch prefix {
	case "+":
		return gchalk.WithBrightRed().Bold(formatted)
	case "-":
		return gchalk.WithBrightGreen().Bold(formatted)
	case "?":
		return gchalk.WithBrightYellow().Bold(formatted)
	default:
		return gchalk.Bold(formatted)
	}
}

func formatSeverity(severity string) string {
	if severity == "" {
		return ""
	}
	colorFn := severityColor(severity)
	return colorFn(severity)
}

func severityColor(severity string) func(...string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return tableprinterutils.GetColorForVulnerabilitySeverity(apis.SeverityCriticalString)
	case "high":
		return tableprinterutils.GetColorForVulnerabilitySeverity(apis.SeverityHighString)
	case "medium":
		return tableprinterutils.GetColorForVulnerabilitySeverity(apis.SeverityMediumString)
	case "low":
		return tableprinterutils.GetColorForVulnerabilitySeverity(apis.SeverityLowString)
	default:
		return tableprinterutils.GetColorForVulnerabilitySeverity(severity)
	}
}

func printSection(w io.Writer, title string, changes []ControlChange, prefix string) error {
	if len(changes) == 0 {
		return nil
	}
	header := fmt.Sprintf("%s (%d)", title, len(changes))
	underline := strings.Repeat("-", len(title)+10)
	styledHeader := header
	styledPrefix := prefix
	switch prefix {
	case "+":
		styledHeader = gchalk.WithBrightRed().Bold(header)
		styledPrefix = gchalk.WithBrightRed().Bold("+")
	case "-":
		styledHeader = gchalk.WithBrightGreen().Bold(header)
		styledPrefix = gchalk.WithBrightGreen().Bold("-")
	case "?":
		styledHeader = gchalk.WithBrightYellow().Bold(header)
		styledPrefix = gchalk.WithBrightYellow().Bold("?")
	}

	if _, err := fmt.Fprintf(w, "\n%s\n%s\n", styledHeader, underline); err != nil {
		return err
	}
	for _, c := range changes {
		if _, err := fmt.Fprintf(w, "%s [%s] %s (%s)\n    Resource: %s\n",
			styledPrefix, formatSeverity(c.Severity), c.ControlName, c.ControlID, c.ResourceID); err != nil {
			return err
		}
		if c.RuleName != "" {
			if _, err := fmt.Fprintf(w, "    Rule: %s\n", c.RuleName); err != nil {
				return err
			}
		}
		if c.EvidenceType != "" && c.EvidenceType != evidenceTypeControl {
			if _, err := fmt.Fprintf(w, "    Evidence: %s", c.EvidenceType); err != nil {
				return err
			}
			if c.Path != "" {
				if _, err := fmt.Fprintf(w, " %s", c.Path); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		if c.EvidenceResourceID != "" && c.EvidenceResourceID != c.ResourceID {
			if _, err := fmt.Fprintf(w, "    Evidence resource: %s\n", c.EvidenceResourceID); err != nil {
				return err
			}
		}
		if c.Reason != "" {
			if _, err := fmt.Fprintf(w, "    Reason: %s\n", c.Reason); err != nil {
				return err
			}
		}
	}
	return nil
}

// PrintJSON writes the ChangeSet as JSON to w.
func PrintJSON(w io.Writer, cs *ChangeSet) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(cs)
}

// PrintYAML writes the ChangeSet as YAML to w.
func PrintYAML(w io.Writer, cs *ChangeSet) error {
	b, err := yaml.Marshal(cs)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}
