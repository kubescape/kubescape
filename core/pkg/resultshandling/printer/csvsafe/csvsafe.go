// Package csvsafe provides spreadsheet formula injection (CWE-1236) neutralization
// and RFC 4180 CSV cell and row sanitization for Kubescape exporters.
//
// Threat Model and Spreadsheet Round-Trip Behavior:
//
// In spreadsheet applications (such as Microsoft Excel, LibreOffice Calc, and
// Google Sheets), cells beginning with formula triggers ('=', '+', '-', '@',
// '\t', '\r', '\n') or leading whitespace followed by these triggers can be
// executed as spreadsheet formulas or Dynamic Data Exchange (DDE) commands upon
// opening, allowing arbitrary code execution or credential exfiltration (CWE-1236).
//
// Standard Mitigation:
// Kubescape neutralizes formula triggers by prepending a single quote ("'").
// Spreadsheets interpret a leading apostrophe as an internal text-prefix indicator:
// the cell content is displayed literally as text without executing formulas or
// DDE payloads, and the leading apostrophe is hidden from the visual interface.
// Other standard CSV consumers (parsers, scripts, diff tools) receive an inert string.
//
// Compatibility Tradeoffs and Alternative Mitigations:
//   - Prepending a tab ('\t'): While recognized by some spreadsheet engines as text,
//     leading tabs distort column alignment, break TSV/tab-delimited parsers, and
//     cause display artifacts in CLI and non-GUI viewers.
//   - Prepending a space (' '): Ineffective on its own because spreadsheet formula
//     evaluators strip leading whitespace before formula syntax parsing (as fixed in #4921).
//   - Outer double-quote wrapping: RFC 4180 parsers strip enclosing quotes during CSV
//     deserialization, leaving the raw formula trigger exposed to the evaluation engine.
//
// Re-export and Security Boundary:
// When a user opens a sanitized CSV in Microsoft Excel, edits it, and saves it back
// to CSV via Excel's "Save As CSV", Excel's own serializer exports the displayed text
// without the leading apostrophe prefix. As a security boundary, Kubescape guarantees
// that the CSV documents it produces are strictly inert upon initial ingestion and
// consumption. Once imported into a third-party spreadsheet editor, subsequent re-exports
// are governed by that application's serializer.
package csvsafe

import (
	"strings"
)

// FormulaPrefixes contains characters that trigger formula evaluation when
// appearing at the beginning of a cell.
const FormulaPrefixes = "=+-@\t\r\n"

// LeadingWhitespaceChars contains whitespace characters that spreadsheet parsers
// strip before inspecting formula trigger prefixes.
const LeadingWhitespaceChars = " \t\r\n\v\f"

// SafeCell neutralizes a cell against spreadsheet formula injection (CWE-1236).
// If the cell begins with a formula trigger ('=', '+', '-', '@', '\t', '\r', '\n'),
// or begins with whitespace followed by any of ('=', '+', '-', '@'), it prepends
// a single quote ("'") to force spreadsheet engines into literal text mode.
// Ordinary text, numbers, whitespace-only cells, and already-safe cells are left unchanged.
func SafeCell(cell string) string {
	if cell == "" {
		return cell
	}
	if strings.ContainsRune(FormulaPrefixes, rune(cell[0])) {
		return "'" + cell
	}
	trimmed := strings.TrimLeft(cell, LeadingWhitespaceChars)
	if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + cell
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
