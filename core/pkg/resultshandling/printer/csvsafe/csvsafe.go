// Package csvsafe neutralizes spreadsheet formula prefixes in Kubescape CSV exports
// (CWE-1236). A leading apostrophe can disappear when a spreadsheet saves the
// cell as CSV. Use ordinary visible text so the marker is part of the value.
// See README.md in this package for the application round-trip results.
package csvsafe

import (
	"strings"
	"unicode"
)

// FormulaPrefixes contains characters that trigger formula evaluation when
// appearing at the beginning of a cell.
const FormulaPrefixes = "=+-@\t\r\n"

// LeadingWhitespaceChars lists the ASCII whitespace characters handled by SafeCell.
const LeadingWhitespaceChars = " \t\r\n\v\f"

const textPrefix = "text: "

// SafeCell preserves the original cell after a visible marker if it starts
// with a trigger, or if an importer could expose one by stripping a prefix.
func SafeCell(cell string) string {
	if cell == "" {
		return cell
	}
	if strings.ContainsRune(FormulaPrefixes, rune(cell[0])) {
		return textPrefix + cell
	}
	// Sheets consumes apostrophes and whitespace. Calc drops NULs on CSV import.
	trimmed := strings.TrimLeftFunc(cell, func(r rune) bool {
		return r == '\'' || r == 0 || unicode.IsSpace(r)
	})
	if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return textPrefix + cell
	}
	return cell
}

// SafeRow applies SafeCell to every cell in row and returns a safe copy.
// The original slice is not modified.
func SafeRow(row []string) []string {
	if row == nil {
		return nil
	}
	out := make([]string, len(row))
	for i := range row {
		out[i] = SafeCell(row[i])
	}
	return out
}
