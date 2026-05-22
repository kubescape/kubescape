package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// PrintPretty writes a human-readable diff summary to w.
func PrintPretty(w io.Writer, cs *ChangeSet) {
	printSection(w, "New failures", cs.New, "+")
	printSection(w, "Resolved", cs.Resolved, "-")
	if len(cs.Unchanged) > 0 {
		printSection(w, "Still failing (unchanged)", cs.Unchanged, " ")
	}

	fmt.Fprintf(w, "\nSummary: %d new, %d resolved, %d unchanged\n",
		len(cs.New), len(cs.Resolved), len(cs.Unchanged))
}

func printSection(w io.Writer, title string, changes []ControlChange, prefix string) {
	if len(changes) == 0 {
		return
	}
	fmt.Fprintf(w, "\n%s (%d)\n%s\n", title, len(changes), strings.Repeat("-", len(title)+10))
	for _, c := range changes {
		fmt.Fprintf(w, "%s [%s] %s (%s)\n    Resource: %s\n",
			prefix, c.Severity, c.ControlName, c.ControlID, c.ResourceID)
	}
}

// PrintJSON writes the ChangeSet as JSON to w.
func PrintJSON(w io.Writer, cs *ChangeSet) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(cs)
}
