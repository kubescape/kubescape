package csvsafe

import (
	"bytes"
	"encoding/csv"
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
		{name: "equals formula is neutralized", in: "=1+1", want: "text: =1+1"},
		{name: "plus formula is neutralized", in: "+1+1", want: "text: +1+1"},
		{name: "minus formula is neutralized", in: "-1-1", want: "text: -1-1"},
		{name: "at-sign formula is neutralized", in: "@SUM(1,2)", want: "text: @SUM(1,2)"},
		{name: "horizontal tab is neutralized", in: "\t=1+1", want: "text: \t=1+1"},
		{name: "carriage return is neutralized", in: "\r=1+1", want: "text: \r=1+1"},
		{name: "line feed is neutralized", in: "\n=1+1", want: "text: \n=1+1"},
		{name: "dde payload is neutralized", in: "=cmd|' /C calc'!A0", want: "text: =cmd|' /C calc'!A0"},
		{name: "leading pipe is not a formula prefix", in: "|table", want: "|table"},
		{name: "leading space before equals is neutralized", in: " =1+1", want: "text:  =1+1"},
		{name: "leading multiple spaces before at is neutralized", in: "   @SUM(A1)", want: "text:    @SUM(A1)"},
		{name: "leading space before plus is neutralized", in: "  +1", want: "text:   +1"},
		{name: "leading space before minus is neutralized", in: "  -1", want: "text:   -1"},
		{name: "leading tab and space before equals is neutralized", in: " \t =cmd", want: "text:  \t =cmd"},
		{name: "leading crlf before equals is neutralized", in: "\r\n=1", want: "text: \r\n=1"},
		{name: "spaces only unchanged", in: "   ", want: "   "},
		{name: "spaces before plain text unchanged", in: "  pod-name", want: "  pod-name"},
		{name: "apostrophe consumed on import", in: "'=1+1", want: "text: '=1+1"},
		{name: "multiple apostrophes before a formula", in: "''=1+1", want: "text: ''=1+1"},
		{name: "whitespace around apostrophe", in: " ' =1+1", want: "text:  ' =1+1"},
		{name: "em space consumed on import", in: "\u2003=1+1", want: "text: \u2003=1+1"},
		{name: "NUL discarded on import", in: "\x00=6*7", want: "text: \x00=6*7"},
		{name: "quoted word unchanged", in: "'pod'", want: "'pod'"},
		{name: "visible prefix preserved", in: "text: =1+1", want: "text: =1+1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, SafeCell(tc.in))
			assert.Equal(t, tc.want, SafeCell(tc.want), "sanitizing twice must preserve the value")
		})
	}
}

func TestSafeRow(t *testing.T) {
	row := []string{"pod-name", "=1+1", "default", "   @SUM(1,2)", "42"}
	original := slicesClone(row)

	safe := SafeRow(row)

	assert.Equal(t, []string{"pod-name", "text: =1+1", "default", "text:    @SUM(1,2)", "42"}, safe)
	assert.Equal(t, original, row, "SafeRow must not mutate the input slice")

	assert.Nil(t, SafeRow(nil))
	assert.Empty(t, SafeRow([]string{}))
}

func TestCSVEncodingRoundTrip(t *testing.T) {
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

	// Check the wire format using Go's CSV reader.
	reader := csv.NewReader(&buf)
	records, err := reader.ReadAll()
	require.NoError(t, err)

	require.Len(t, records, len(rawRows)+1)
	assert.Equal(t, headers, records[0], "header row must match exactly")

	for i, row := range rawRows {
		assert.Equal(t, SafeRow(row), records[i+1])
	}
}

func slicesClone(s []string) []string {
	c := make([]string, len(s))
	copy(c, s)
	return c
}
