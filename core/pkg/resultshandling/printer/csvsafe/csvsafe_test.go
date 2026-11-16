package csvsafe

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSafeCell(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty cell unchanged", in: "", want: ""},
		{name: "plain text unchanged", in: "pod-name", want: "pod-name"},
		{name: "plain number unchanged", in: "42", want: "42"},
		{name: "equals formula is neutralized", in: "=1+1", want: "'=1+1"},
		{name: "plus formula is neutralized", in: "+1+1", want: "'+1+1"},
		{name: "minus formula is neutralized", in: "-1-1", want: "'-1-1"},
		{name: "at-sign formula is neutralized", in: "@SUM(1,2)", want: "'@SUM(1,2)"},
		{name: "horizontal tab is neutralized", in: "\t=1+1", want: "'\t=1+1"},
		{name: "carriage return is neutralized", in: "\r=1+1", want: "'\r=1+1"},
		{name: "line feed is neutralized", in: "\n=1+1", want: "'\n=1+1"},
		{name: "dde payload is neutralized", in: "=cmd|' /C calc'!A0", want: "'=cmd|' /C calc'!A0"},
		{name: "leading pipe is not a formula prefix", in: "|table", want: "|table"},
		{name: "leading space before equals is neutralized", in: " =1+1", want: "' =1+1"},
		{name: "leading multiple spaces before at is neutralized", in: "   @SUM(A1)", want: "'   @SUM(A1)"},
		{name: "leading space before plus is neutralized", in: "  +1", want: "'  +1"},
		{name: "leading space before minus is neutralized", in: "  -1", want: "'  -1"},
		{name: "leading tab and space before equals is neutralized", in: " \t =cmd", want: "' \t =cmd"},
		{name: "leading crlf before equals is neutralized", in: "\r\n=1", want: "'\r\n=1"},
		{name: "spaces only unchanged", in: "   ", want: "   "},
		{name: "spaces before plain text unchanged", in: "  pod-name", want: "  pod-name"},
		{name: "already neutralized cell is not double-prefixed", in: "'=1+1", want: "'=1+1"},
		{name: "already neutralized cell with space is not double-prefixed", in: "' =1+1", want: "' =1+1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, SafeCell(tc.in))
		})
	}
}

func TestSafeRow(t *testing.T) {
	row := []string{"pod-name", "=1+1", "default", "   @SUM(1,2)", "42"}
	original := slicesClone(row)

	safe := SafeRow(row)

	assert.Equal(t, []string{"pod-name", "'=1+1", "default", "'   @SUM(1,2)", "42"}, safe)
	assert.Equal(t, original, row, "SafeRow must not mutate the input slice")

	assert.Nil(t, SafeRow(nil))
	assert.Empty(t, SafeRow([]string{}))
}

// TestSpreadsheetRoundTrip validates end-to-end RFC 4180 CSV serialization
// and re-opening, verifying that:
// 1. Sanitized formula cells retain their safe leading apostrophe after decoding.
// 2. CSV delimiter parsing (commas, quotes, newlines) is preserved without corruption.
// 3. Re-running SafeCell on round-tripped records is strictly idempotent.
func TestSpreadsheetRoundTrip(t *testing.T) {
	headers := []string{"Cluster", "Namespace", "Kind", "Name", "ControlID", "Description"}
	rawRows := [][]string{
		{"prod-cluster", "default", "Deployment", "nginx", "C-0001", "Regular workload"},
		{"prod-cluster", "kube-system", "Pod", "=cmd|' /C calc'!A0", "C-0002", "DDE attack in name"},
		{"prod-cluster", "finance", "Service", "  @SUM(1,2)", "C-0003", "Formula with leading whitespace"},
		{"prod-cluster", "dev", "ConfigMap", "+12345", "C-0004", "Plus sign prefix"},
		{"prod-cluster", "test", "Secret", "-secret-value", "C-0005", "Hyphen prefix"},
		{"prod-cluster", "logging", "DaemonSet", "fluentd", "C-0006", "Description with, comma and \"quotes\" and\nnewline"},
		{"prod-cluster", "monitoring", "StatefulSet", "|table-pipe", "C-0007", "Pipe character should remain literal"},
	}

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write header row
	require.NoError(t, writer.Write(SafeRow(headers)))

	// Write sanitized data rows
	for _, row := range rawRows {
		require.NoError(t, writer.Write(SafeRow(row)))
	}
	writer.Flush()
	require.NoError(t, writer.Error())

	// Read back through standard RFC 4180 CSV reader (simulating spreadsheet ingestion)
	reader := csv.NewReader(&buf)
	records, err := reader.ReadAll()
	require.NoError(t, err)

	require.Len(t, records, len(rawRows)+1)
	assert.Equal(t, headers, records[0], "header row must match exactly")

	// Verify each data row after round-trip
	for i, record := range records[1:] {
		orig := rawRows[i]
		require.Len(t, record, len(orig))

		for colIdx, cell := range record {
			origCell := orig[colIdx]

			// Verify that dangerous formula cells now carry the safe apostrophe
			trimmed := strings.TrimLeft(origCell, LeadingWhitespaceChars)
			if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
				assert.True(t, strings.HasPrefix(cell, "'"),
					"cell %q (original %q) must begin with safe apostrophe", cell, origCell)
			}

			// Verify cell content preservation for benign cells with complex delimiters
			if origCell == "Description with, comma and \"quotes\" and\nnewline" {
				assert.Equal(t, origCell, cell, "delimiters, quotes, and newlines must survive round-trip")
			}
			if origCell == "|table-pipe" {
				assert.Equal(t, "|table-pipe", cell, "pipes must not be modified")
			}

			// Idempotence: re-sanitizing decoded cells must produce the exact same text
			assert.Equal(t, cell, SafeCell(cell),
				"SafeCell must be idempotent on round-tripped cell %q", cell)
		}
	}
}

// TestExcelPrefixStrippingResilience documents and verifies the scenario where
// a spreadsheet editor (like Microsoft Excel) strips the leading apostrophe
// when re-saving a modified sheet to CSV.
func TestExcelPrefixStrippingResilience(t *testing.T) {
	// 1. Kubescape exports a sanitized cell
	exported := SafeCell("=cmd|' /C calc'!A0")
	assert.Equal(t, "'=cmd|' /C calc'!A0", exported)

	// 2. When Excel opens '=cmd, it treats ' as the text-prefix indicator and displays =cmd.
	// When saved back as CSV from Excel, Excel writes the displayed text without the ':
	excelReExported := strings.TrimPrefix(exported, "'")
	assert.Equal(t, "=cmd|' /C calc'!A0", excelReExported)

	// 3. If that re-exported CSV is fed back into Kubescape or sanitized again,
	// SafeCell reliably neutralizes it once more.
	reSanitized := SafeCell(excelReExported)
	assert.Equal(t, "'=cmd|' /C calc'!A0", reSanitized)
}

func slicesClone(s []string) []string {
	c := make([]string, len(s))
	copy(c, s)
	return c
}
