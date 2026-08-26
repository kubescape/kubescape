package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"sigs.k8s.io/yaml"
)

// PrintPretty writes a human-readable diff summary to w.
func PrintPretty(w io.Writer, cs *ChangeSet) error {
	for _, warning := range cs.Warnings {
		if _, err := fmt.Fprintf(w, "WARNING: %s\n", warning); err != nil {
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

	_, err := fmt.Fprintf(w, "\nSummary: %d new, %d resolved, %d unchanged, %d incomparable\n",
		len(cs.New), len(cs.Resolved), len(cs.Unchanged), len(cs.Incomparable))
	return err
}

func printSection(w io.Writer, title string, changes []ControlChange, prefix string) error {
	if len(changes) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(w, "\n%s (%d)\n%s\n", title, len(changes), strings.Repeat("-", len(title)+10)); err != nil {
		return err
	}
	for _, c := range changes {
		if _, err := fmt.Fprintf(w, "%s [%s] %s (%s)\n    Resource: %s\n",
			prefix, c.Severity, c.ControlName, c.ControlID, c.ResourceID); err != nil {
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
