package core

import (
	"context"
	"encoding/csv"
	"io"
	"os"
	"strings"
	"testing"

	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
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

func readCSVRecords(t *testing.T, content string) [][]string {
	t.Helper()

	r := csv.NewReader(strings.NewReader(content))
	records, err := r.ReadAll()
	require.NoError(t, err)
	return records
}
