// Generate the spreadsheet round-trip fixture on stdout.
package main

import (
	"encoding/csv"
	"log"
	"os"

	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/csvsafe"
)

func main() {
	w := csv.NewWriter(os.Stdout)
	// The raw arithmetic control establishes whether this import evaluates formulas.
	rows := [][]string{{"case", "value"}, {"raw control", "=6*7"}}
	for _, row := range [][]string{
		{"equals", "=6*7"},
		{"plus", "+6*7"},
		{"minus", "-6*7"},
		{"at", "@SUM(6,7)"},
		{"space", "  =6*7"},
		{"tab", "\t=6*7"},
		{"carriage return", "\r=6*7"},
		{"line feed", "\n=6*7"},
		{"already prefixed", "'=6*7"},
		{"embedded quotes", `="a,b"&"c"`},
		{"ordinary text", `pod, "web"`},
		{"em space", "\u2003=6*7"},
		{"leading NUL", "\x00=6*7"},
	} {
		rows = append(rows, csvsafe.SafeRow(row))
	}
	if err := w.WriteAll(rows); err != nil {
		log.Fatal(err)
	}
}
