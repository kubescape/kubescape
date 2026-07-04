package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeReport writes raw scan-report JSON to a temp file and returns its path.
func writeReport(t *testing.T, json string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "report-*.json")
	require.NoError(t, err)
	_, err = f.WriteString(json)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

// TestDiff_ReturnsNewFailureCount verifies that Diff returns the number of new failures at or above the severity threshold.
func TestDiff_ReturnsNewFailureCount(t *testing.T) {
	base := writeReport(t, `{"results":[],"summaryDetails":{"controls":{}}}`)
	head := writeReport(t, `{
		"results":[{"resourceID":"res1","controls":[
			{"controlID":"C-HIGH","name":"High","status":{"status":"failed"}},
			{"controlID":"C-LOW","name":"Low","status":{"status":"failed"}}
		]}],
		"summaryDetails":{"controls":{
			"C-HIGH":{"scoreFactor":7.0},
			"C-LOW":{"scoreFactor":2.0}
		}}
	}`)

	ks := NewKubescape(context.Background())
	outDir := t.TempDir()

	t.Run("no threshold counts all new failures", func(t *testing.T) {
		count, err := ks.Diff(&metav1.DiffInfo{
			BaseFile: base,
			HeadFile: head,
			Format:   "json",
			Output:   filepath.Join(outDir, "all.json"),
		})
		require.NoError(t, err)
		assert.Equal(t, 2, count)
	})

	t.Run("high threshold counts only high+ new failures", func(t *testing.T) {
		out := filepath.Join(outDir, "high.json")
		count, err := ks.Diff(&metav1.DiffInfo{
			BaseFile:          base,
			HeadFile:          head,
			Format:            "json",
			SeverityThreshold: "high",
			Output:            out,
		})
		require.NoError(t, err)
		assert.Equal(t, 1, count)

		// The deferred writer close must have run: the output file is present and non-empty.
		data, err := os.ReadFile(out)
		require.NoError(t, err)
		assert.NotEmpty(t, data)
	})

	t.Run("no new failures returns zero", func(t *testing.T) {
		count, err := ks.Diff(&metav1.DiffInfo{
			BaseFile: head,
			HeadFile: head,
			Format:   "json",
			Output:   filepath.Join(outDir, "same.json"),
		})
		require.NoError(t, err)
		assert.Equal(t, 0, count)
	})
}

// TestDiff_PrettyFormatWritesOutput verifies the pretty-printer output path.
func TestDiff_PrettyFormatWritesOutput(t *testing.T) {
	base := writeReport(t, `{"results":[],"summaryDetails":{"controls":{}}}`)
	head := writeReport(t, `{
		"results":[{"resourceID":"res1","controls":[
			{"controlID":"C-HIGH","name":"High","status":{"status":"failed"}}
		]}],
		"summaryDetails":{"controls":{"C-HIGH":{"scoreFactor":7.0}}}
	}`)
	ks := NewKubescape(context.Background())
	out := filepath.Join(t.TempDir(), "pretty.out")
	count, err := ks.Diff(&metav1.DiffInfo{
		BaseFile: base,
		HeadFile: head,
		Format:   "pretty-printer",
		Output:   out,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, count)
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Contains(t, string(data), "New failures")
}
