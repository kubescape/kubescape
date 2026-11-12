//go:build windows

package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiffOutputPath_BareWindowsDrive(t *testing.T) {
	dir := t.TempDir()
	drive := filepath.VolumeName(dir)
	if !strings.HasSuffix(drive, ":") {
		t.Skip("test requires a drive-letter volume")
	}
	// Use a directory below the drive root so drive-relative and absolute
	// paths have different destinations. A bare drive must reach the
	// existing-directory branch that caused the regression.
	t.Chdir(dir)
	info, err := os.Stat(drive)
	require.NoError(t, err)
	require.True(t, info.IsDir())

	cases := []struct {
		name   string
		format string
		input  string
		want   string
	}{
		{"bare drive with JSON", "json", drive, drive + "diff.json"},
		{"bare drive with summary YAML", "summary-yaml", drive, drive + "diff.yaml"},
		{"bare drive with pretty output", "pretty-printer", drive, drive + "diff"},
		{"drive root with backslash", "json", drive + `\`, drive + `\diff.json`},
		{"drive root with forward slash", "json", drive + "/", drive + "/diff.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, explicit := diffOutputPath(tc.format, tc.input)
			assert.True(t, explicit)
			assert.Equal(t, tc.want, got)
		})
	}

	t.Run("diff writes in the drive current directory", func(t *testing.T) {
		report := writeReport(t, `{"results":[],"summaryDetails":{"controls":{}}}`)
		ks := NewKubescape(context.Background())
		count, err := ks.Diff(&metav1.DiffInfo{
			BaseFile: report,
			HeadFile: report,
			Format:   "json",
			Output:   drive,
		})
		require.NoError(t, err)
		assert.Zero(t, count)

		data, err := os.ReadFile(filepath.Join(dir, "diff.json"))
		require.NoError(t, err)
		assert.NotEmpty(t, data)
	})
}
