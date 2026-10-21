package core

import (
	"context"
	"encoding/csv"
	"io"
	"os"
	"strings"
	"testing"

	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	rescueStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() {
		os.Stdout = rescueStdout
		_ = r.Close()
		_ = w.Close()
	}()

	fn()

	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

func TestCSVListFormat_RendersPolicyNames(t *testing.T) {
	out := captureStdout(t, func() {
		csvListFormat(context.Background(), "frameworks", []string{"nsa", "mitre"})
	})

	records := readCSVRecords(t, out)
	require.Len(t, records, 3)
	assert.Equal(t, []string{"name"}, records[0])
	assert.Equal(t, []string{"nsa"}, records[1])
	assert.Equal(t, []string{"mitre"}, records[2])
}

func TestCSVControlsFormat_RendersStructuredRows(t *testing.T) {
	entries := []metav1.ControlListEntry{
		{ID: "C-0001", Name: "Forbidden Registries", Frameworks: []string{"NSA", "MITRE"}},
		{ID: "C-0002", Name: "Privileged Containers", Frameworks: []string{"AllControls"}},
	}

	out := captureStdout(t, func() {
		csvControlsFormat(entries)
	})

	records := readCSVRecords(t, out)
	require.Len(t, records, 3)
	assert.Equal(t, []string{"id", "name", "frameworks"}, records[0])
	assert.Equal(t, []string{"C-0001", "Forbidden Registries", "NSA;MITRE"}, records[1])
	assert.Equal(t, []string{"C-0002", "Privileged Containers", "AllControls"}, records[2])
}

func TestPrintListResult_CSVFormats(t *testing.T) {
	result := &metav1.ListResult{Names: []string{"nsa"}, Controls: []metav1.ControlListEntry{{ID: "C-0001", Name: "Forbidden Registries", Frameworks: []string{"NSA"}}}}

	out := captureStdout(t, func() {
		require.NoError(t, PrintListResult(context.Background(), result, "frameworks", "csv"))
	})

	records := readCSVRecords(t, out)
	require.Len(t, records, 2)
	assert.Equal(t, []string{"name"}, records[0])
	assert.Equal(t, []string{"nsa"}, records[1])
}

func TestCSVControlsConfigFormat_RendersStructuredRows(t *testing.T) {
	entries := []metav1.ControlConfigEntry{
		{
			Name:        "imageRepositoryAllowList",
			Title:       "Image repository allow list",
			Values:      []string{"quay.io", "registry.k8s.io"},
			Controls:    []string{"C-0001", "C-0002"},
			Description: "Permitted image registries",
		},
	}

	out := captureStdout(t, func() {
		csvControlsConfigFormat(entries)
	})

	records := readCSVRecords(t, out)
	require.Len(t, records, 2)
	assert.Equal(t, []string{"name", "title", "values", "controls", "description"}, records[0])
	assert.Equal(t, []string{"imageRepositoryAllowList", "Image repository allow list", "quay.io;registry.k8s.io", "C-0001;C-0002", "Permitted image registries"}, records[1])
}

// TestCsvSafeCell_List verifies that cells starting with spreadsheet formula
// prefix characters (=, +, -, @, \t, \r, \n) are prepended with a single quote.
func TestCsvSafeCell_List(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty stays empty", in: "", want: ""},
		{name: "plain text is unchanged", in: "demo", want: "demo"},
		{name: "equals is neutralized", in: "=1+1", want: "'=1+1"},
		{name: "plus is neutralized", in: "+1", want: "'+1"},
		{name: "minus is neutralized", in: "-1", want: "'-1"},
		{name: "at sign is neutralized", in: "@SUM(A1)", want: "'@SUM(A1)"},
		{name: "tab is neutralized", in: "\tcmd", want: "'\tcmd"},
		{name: "carriage return is neutralized", in: "\rcmd", want: "'\rcmd"},
		{name: "line feed is neutralized", in: "\n=1+1", want: "'\n=1+1"},
		{name: "dde payload is neutralized", in: "=cmd|' /C calc'!A0", want: "'=cmd|' /C calc'!A0"},
		{name: "leading pipe is not a formula prefix", in: "|table", want: "|table"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, csvSafeCell(tc.in))
		})
	}
}

func TestCSVListFormat_NeutralizesFormulaInjection(t *testing.T) {
	policies := []string{
		"=cmd|' /C calc'!A0",
		"@SUM(A1)",
		"+nsa",
		"-mitre",
		"normal-policy",
	}

	out := captureStdout(t, func() {
		csvListFormat(context.Background(), "frameworks", policies)
	})

	records := readCSVRecords(t, out)
	require.Len(t, records, 6)
	assert.Equal(t, []string{"name"}, records[0])
	assert.Equal(t, []string{"'=cmd|' /C calc'!A0"}, records[1])
	assert.Equal(t, []string{"'@SUM(A1)"}, records[2])
	assert.Equal(t, []string{"'+nsa"}, records[3])
	assert.Equal(t, []string{"'-mitre"}, records[4])
	assert.Equal(t, []string{"normal-policy"}, records[5])
}

func TestCSVControlsFormat_NeutralizesFormulaInjection(t *testing.T) {
	entries := []metav1.ControlListEntry{
		{
			ID:         "+C-0001",
			Name:       "=cmd|' /C calc'!A0",
			Frameworks: []string{"@NSA", "-MITRE"},
		},
	}

	out := captureStdout(t, func() {
		csvControlsFormat(entries)
	})

	records := readCSVRecords(t, out)
	require.Len(t, records, 2)
	assert.Equal(t, []string{"id", "name", "frameworks"}, records[0])
	assert.Equal(t, []string{"'+C-0001", "'=cmd|' /C calc'!A0", "'@NSA;-MITRE"}, records[1])
}

func TestCSVControlsConfigFormat_NeutralizesFormulaInjection(t *testing.T) {
	entries := []metav1.ControlConfigEntry{
		{
			Name:        "=secretParam",
			Title:       "@dangerousTitle",
			Values:      []string{"+evilVal1", "val2"},
			Controls:    []string{"-C-0001"},
			Description: "=calc()",
		},
	}

	out := captureStdout(t, func() {
		csvControlsConfigFormat(entries)
	})

	records := readCSVRecords(t, out)
	require.Len(t, records, 2)
	assert.Equal(t, []string{"name", "title", "values", "controls", "description"}, records[0])
	assert.Equal(t, []string{
		"'=secretParam",
		"'@dangerousTitle",
		"'+evilVal1;val2",
		"'-C-0001",
		"'=calc()",
	}, records[1])
}

func readCSVRecords(t *testing.T, content string) [][]string {
	t.Helper()

	r := csv.NewReader(strings.NewReader(content))
	records, err := r.ReadAll()
	require.NoError(t, err)
	return records
}
