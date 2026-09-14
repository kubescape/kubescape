package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type failingCloser struct {
	err error
}

func (c failingCloser) Close() error {
	return c.err
}

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

// TestDiff_ReturnsNewFailureCount verifies that Diff returns the number of new or incomparable failures at or above the severity threshold.
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

	t.Run("scope mismatch counts incomparable failures", func(t *testing.T) {
		baseScoped := writeReport(t, `{
			"results":[{"resourceID":"res1","controls":[
				{"controlID":"C-HIGH","name":"High","status":{"status":"failed"}}
			]}],
			"summaryDetails":{"controls":{"C-HIGH":{"scoreFactor":7.0}}},
			"metadata":{"scanMetadata":{"excludedNamespaces":["kube-system"]}}
		}`)
		headScoped := writeReport(t, `{
			"results":[{"resourceID":"res1","controls":[
				{"controlID":"C-HIGH","name":"High","status":{"status":"failed"}}
			]}],
			"summaryDetails":{"controls":{"C-HIGH":{"scoreFactor":7.0}}},
			"metadata":{"scanMetadata":{"excludedNamespaces":["kube-system","monitoring"]}}
		}`)

		count, err := ks.Diff(&metav1.DiffInfo{
			BaseFile:          baseScoped,
			HeadFile:          headScoped,
			Format:            "json",
			SeverityThreshold: "high",
			Output:            filepath.Join(outDir, "scope.json"),
		})
		require.NoError(t, err)
		assert.Equal(t, 1, count)
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

func TestDiff_MachineFormatsWriteExpectedOutputFiles(t *testing.T) {
	base := writeReport(t, `{"results":[],"summaryDetails":{"controls":{}}}`)
	head := writeReport(t, `{
		"results":[{"resourceID":"res1","controls":[
			{"controlID":"C-HIGH","name":"High","status":{"status":"failed"}}
		]}],
		"summaryDetails":{"controls":{"C-HIGH":{"scoreFactor":7.0}}}
	}`)

	tests := []struct {
		name       string
		format     string
		outputBase string
		wantFile   string
		wantText   string
	}{
		{
			name:       "sarif appends extension",
			format:     "sarif",
			outputBase: "kubescape-diff",
			wantFile:   "kubescape-diff.sarif",
			wantText:   `"version": "2.1.0"`,
		},
		{
			name:       "junit appends extension",
			format:     "junit",
			outputBase: "kubescape-diff",
			wantFile:   "kubescape-diff.xml",
			wantText:   `<testsuites name="Kubescape Diff" tests="1" failures="1" errors="0">`,
		},
		{
			name:       "gitlab-sast appends json extension",
			format:     "gitlab-sast",
			outputBase: "gl-sast-report",
			wantFile:   "gl-sast-report.json",
			wantText:   `"version": "15.2.4"`,
		},
		{
			name:       "summary-json appends json extension",
			format:     "summary-json",
			outputBase: "kubescape-diff-summary",
			wantFile:   "kubescape-diff-summary.json",
			wantText:   `"regressions":`,
		},
		{
			name:       "summary-yaml appends yaml extension",
			format:     "summary-yaml",
			outputBase: "kubescape-diff-summary",
			wantFile:   "kubescape-diff-summary.yaml",
			wantText:   "regressions:",
		},
		{
			name:       "summary-csv appends csv extension",
			format:     "summary-csv",
			outputBase: "kubescape-diff-summary",
			wantFile:   "kubescape-diff-summary.csv",
			wantText:   "section,key,bucket,severity,control_id,control_name,resource_id,count",
		},
		{
			name:       "markdown appends extension",
			format:     "markdown",
			outputBase: "kubescape-diff",
			wantFile:   "kubescape-diff.md",
			wantText:   "# Kubescape Diff Regressions",
		},
		{
			name:       "yaml accepts yml extension",
			format:     "yaml",
			outputBase: "kubescape-diff.yml",
			wantFile:   "kubescape-diff.yml",
			wantText:   "new:",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outDir := t.TempDir()
			ks := NewKubescape(context.Background())
			count, err := ks.Diff(&metav1.DiffInfo{
				BaseFile: base,
				HeadFile: head,
				Format:   test.format,
				Output:   filepath.Join(outDir, test.outputBase),
			})

			require.NoError(t, err)
			assert.Equal(t, 1, count)

			data, err := os.ReadFile(filepath.Join(outDir, test.wantFile))
			require.NoError(t, err)
			assert.Contains(t, string(data), test.wantText)
		})
	}
}

func TestDiffOutputPath(t *testing.T) {
	tests := []struct {
		name         string
		format       string
		outputFile   string
		want         string
		wantExplicit bool
	}{
		{"empty output stays empty", "sarif", "", "", false},
		{"blank output stays explicit", "sarif", " ", "", true},
		{"whitespace is trimmed", "sarif", " report ", "report.sarif", true},
		{"known extension is appended", "sarif", "report", "report.sarif", true},
		{"existing extension is preserved", "sarif", "report.sarif", "report.sarif", true},
		{"existing extension comparison is case-insensitive", "sarif", "report.SARIF", "report.SARIF", true},
		{"summary-json appends json extension", "summary-json", "report", "report.json", true},
		{"summary-json preserves json extension", "summary-json", "report.JSON", "report.JSON", true},
		{"summary-yaml appends yaml extension", "summary-yaml", "report", "report.yaml", true},
		{"summary-yaml preserves yaml extension", "summary-yaml", "report.YAML", "report.YAML", true},
		{"summary-yaml preserves yml extension", "summary-yaml", "report.yml", "report.yml", true},
		{"summary-csv appends csv extension", "summary-csv", "report", "report.csv", true},
		{"summary-csv preserves csv extension", "summary-csv", "report.CSV", "report.CSV", true},
		{"pretty output path stays exact", "pretty-printer", "pretty.out", "pretty.out", true},
		{"yaml accepts yml", "yaml", "report.yml", "report.yml", true},
		{"unknown format is untouched", "unknown", "report", "report", true},
		{"stdout sink resolves to no file", "json", os.Stdout.Name(), "", false},
		{"pretty stdout sink resolves to no file", "pretty-printer", os.Stdout.Name(), "", false},
		{"devnull sink keeps exact path", "sarif", os.DevNull, os.DevNull, true},
		{"summary-json stdout sink resolves to no file", "summary-json", os.Stdout.Name(), "", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotExplicit := diffOutputPath(test.format, test.outputFile)
			assert.Equal(t, test.want, got)
			assert.Equal(t, test.wantExplicit, gotExplicit)
		})
	}
}

// TestDiff_StdoutSinkWritesThroughExistingStdout checks the writer behind the
// stdout sink, not just the path it resolves to: the diff must go through the
// descriptor os.Stdout already holds, appending to whatever stdout was
// redirected to instead of reopening and truncating that path, and the
// borrowed descriptor must still be usable after Diff returns.
func TestDiff_StdoutSinkWritesThroughExistingStdout(t *testing.T) {
	base := writeReport(t, `{"results":[],"summaryDetails":{"controls":{}}}`)
	head := writeReport(t, `{
		"results":[{"resourceID":"res1","controls":[
			{"controlID":"C-HIGH","name":"High","status":{"status":"failed"}}
		]}],
		"summaryDetails":{"controls":{"C-HIGH":{"scoreFactor":7.0}}}
	}`)

	const prelude = "written before the diff\n"
	redirect := filepath.Join(t.TempDir(), "redirected-stdout")
	require.NoError(t, os.WriteFile(redirect, []byte(prelude), 0o600))
	fakeStdout, err := os.OpenFile(redirect, os.O_WRONLY|os.O_APPEND, 0o600)
	require.NoError(t, err)

	realStdout := os.Stdout
	os.Stdout = fakeStdout
	defer func() {
		os.Stdout = realStdout
		_ = fakeStdout.Close()
	}()

	ks := NewKubescape(context.Background())
	count, err := ks.Diff(&metav1.DiffInfo{
		BaseFile: base,
		HeadFile: head,
		Format:   "json",
		Output:   os.Stdout.Name(),
	})
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Diff borrowed this descriptor, so it must not have closed it.
	_, err = os.Stdout.WriteString("written after the diff\n")
	require.NoError(t, err, "Diff closed the process stdout descriptor")

	require.NoError(t, fakeStdout.Sync())
	data, err := os.ReadFile(redirect)
	require.NoError(t, err)
	written := string(data)
	assert.True(t, strings.HasPrefix(written, prelude), "stdout redirection was truncated: %q", written)
	assert.Contains(t, written, "C-HIGH")
	assert.Contains(t, written, "written after the diff")
}

func TestDiff_ExplicitOutputSetupFailureIsReturned(t *testing.T) {
	base := writeReport(t, `{"results":[],"summaryDetails":{"controls":{}}}`)
	head := writeReport(t, `{"results":[],"summaryDetails":{"controls":{}}}`)

	blocker := filepath.Join(t.TempDir(), "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("not a directory"), 0o600))

	ks := NewKubescape(context.Background())
	_, err := ks.Diff(&metav1.DiffInfo{
		BaseFile: base,
		HeadFile: head,
		Format:   "pretty-printer",
		Output:   filepath.Join(blocker, "diff.out"),
	})
	require.ErrorContains(t, err, "opening diff output")
}

func TestDiff_PrettyWriteFailureIsReturned(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("requires /dev/full")
	}

	base := writeReport(t, `{"results":[],"summaryDetails":{"controls":{}}}`)
	head := writeReport(t, `{
		"results":[{"resourceID":"res1","controls":[
			{"controlID":"C-HIGH","name":"High","status":{"status":"failed"}}
		]}],
		"summaryDetails":{"controls":{"C-HIGH":{"scoreFactor":7.0}}}
	}`)

	ks := NewKubescape(context.Background())
	_, err := ks.Diff(&metav1.DiffInfo{
		BaseFile: base,
		HeadFile: head,
		Format:   "pretty-printer",
		Output:   "/dev/full",
	})
	require.ErrorContains(t, err, "writing pretty diff")
}

func TestCloseDiffOutput_JoinsCloseError(t *testing.T) {
	writeErr := errors.New("write failed")
	closeErr := errors.New("close failed")

	err := closeDiffOutput(failingCloser{err: closeErr}, writeErr)
	require.ErrorIs(t, err, writeErr)
	require.ErrorIs(t, err, closeErr)
}
