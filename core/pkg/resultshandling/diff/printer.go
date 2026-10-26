package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jwalton/gchalk"
	tableprinterutils "github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/mattn/go-isatty"
	"sigs.k8s.io/yaml"
)

var (
	isTerminal       = isatty.IsTerminal
	isCygwinTerminal = isatty.IsCygwinTerminal
)

func shouldColor(w io.Writer) bool {
	if _, set := os.LookupEnv("NO_COLOR"); set {
		return false
	}
	if gchalk.GetLevel() == gchalk.LevelNone {
		return false
	}
	if f, ok := w.(*os.File); ok {
		if os.Getenv("FORCE_COLOR") != "" && os.Getenv("FORCE_COLOR") != "0" {
			return true
		}
		return isTerminal(f.Fd()) || isCygwinTerminal(f.Fd())
	}
	return true
}

// PrintPretty writes a human-readable diff summary to w.
func PrintPretty(w io.Writer, cs *ChangeSet) error {
	colored := shouldColor(w)
	for _, warning := range cs.Warnings {
		warnLabel := "WARNING:"
		if colored {
			warnLabel = gchalk.WithBrightYellow().Bold("WARNING:")
		}
		if _, err := fmt.Fprintf(w, "%s %s\n", warnLabel, warning); err != nil {
			return err
		}
	}
	if err := printSection(w, "New failures", cs.New, "+", colored); err != nil {
		return err
	}
	if err := printSection(w, "Resolved", cs.Resolved, "-", colored); err != nil {
		return err
	}
	if len(cs.Unchanged) > 0 {
		if err := printSection(w, "Still failing (unchanged)", cs.Unchanged, " ", colored); err != nil {
			return err
		}
	}
	if len(cs.Incomparable) > 0 {
		if err := printSection(w, "Incomparable", cs.Incomparable, "?", colored); err != nil {
			return err
		}
	}

	_, err := fmt.Fprintf(w, "\nSummary: %s new, %s resolved, %s unchanged, %s incomparable\n",
		formatSummaryCount(len(cs.New), "+", colored),
		formatSummaryCount(len(cs.Resolved), "-", colored),
		formatSummaryCount(len(cs.Unchanged), " ", colored),
		formatSummaryCount(len(cs.Incomparable), "?", colored),
	)
	return err
}

func formatSummaryCount(count int, prefix string, colored bool) string {
	formatted := fmt.Sprintf("%d", count)
	if !colored {
		return formatted
	}
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

func formatSeverity(severity string, colored bool) string {
	if severity == "" {
		return ""
	}
	if !colored {
		return severity
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
	case "negligible":
		return tableprinterutils.GetColorForVulnerabilitySeverity(apis.SeverityNegligibleString)
	case "unknown":
		return tableprinterutils.GetColorForVulnerabilitySeverity(apis.SeverityUnknownString)
	default:
		return tableprinterutils.GetColorForVulnerabilitySeverity(severity)
	}
}

func printSection(w io.Writer, title string, changes []ControlChange, prefix string, colored bool) error {
	if len(changes) == 0 {
		return nil
	}
	header := fmt.Sprintf("%s (%d)", title, len(changes))
	underline := strings.Repeat("-", len(title)+10)
	styledHeader := header
	styledPrefix := prefix
	if colored {
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
	}

	if _, err := fmt.Fprintf(w, "\n%s\n%s\n", styledHeader, underline); err != nil {
		return err
	}
	for _, c := range changes {
		if _, err := fmt.Fprintf(w, "%s [%s] %s (%s)\n    Resource: %s\n",
			styledPrefix, formatSeverity(c.Severity, colored), c.ControlName, c.ControlID, c.ResourceID); err != nil {
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
