package printer

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsPrintSeparatorType(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
		scanType cautils.ScanTypes
	}{
		{
			name:     "cluster scan",
			scanType: cautils.ScanTypeCluster,
			expected: false,
		},
		{
			name:     "repo scan",
			scanType: cautils.ScanTypeRepo,
			expected: false,
		},
		{
			name:     "workload scan",
			scanType: cautils.ScanTypeWorkload,
			expected: false,
		},
		{
			name:     "control scan",
			scanType: cautils.ScanTypeControl,
			expected: true,
		},
		{
			name:     "framework scan",
			scanType: cautils.ScanTypeFramework,
			expected: true,
		},
		{
			name:     "image scan",
			scanType: cautils.ScanTypeImage,
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := isPrintSeparatorType(test.scanType)
			if got != test.expected {
				t.Errorf("%s failed - expected %t, got %t", test.name, test.expected, got)
			}
		})
	}
}

// newTestPrettyPrinterFile creates a PrettyPrinter backed by a temp file and
// returns the printer and a teardown function that reads and removes the file.
func newTestPrettyPrinterFile(t *testing.T) (*PrettyPrinter, func() string) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "pp-test-*.txt")
	require.NoError(t, err)
	pp := &PrettyPrinter{writer: f}
	return pp, func() string {
		f.Close()
		data, err := os.ReadFile(f.Name())
		require.NoError(t, err)
		return string(data)
	}
}

// TestPrintScanCoverage_PartialOnlyRendered verifies that a ScanCoverage with
// only PartialGVRPulls (no whole-GVR failures) is still rendered. Prior to the
// fix, the early-return guard checked only FailedGVRPulls and
// NotEvaluatedControls, so a partial-only scan produced no CLI output at all.
func TestPrintScanCoverage_PartialOnlyRendered(t *testing.T) {
	pp, read := newTestPrettyPrinterFile(t)

	coverage := cautils.ScanCoverage{
		PartialGVRPulls: []cautils.PartialGVRPull{
			{GVR: "/v1/pods", Selector: "metadata.namespace=prod", Error: "forbidden for prod"},
		},
	}
	pp.printScanCoverage(coverage)

	out := read()
	assert.Contains(t, out, "Scan Coverage Warning", "header must appear for partial-only coverage")
	assert.Contains(t, out, "/v1/pods", "GVR must appear in output")
	assert.Contains(t, out, "metadata.namespace=prod", "selector must appear in output")
	assert.Contains(t, out, "incomplete data", "incomplete-data notice must appear")
}

// TestPrintScanCoverage_CleanScanNoOutput verifies no output is produced when
// the coverage struct is completely empty.
func TestPrintScanCoverage_CleanScanNoOutput(t *testing.T) {
	pp, read := newTestPrettyPrinterFile(t)
	pp.printScanCoverage(cautils.ScanCoverage{})
	assert.Empty(t, read())
}

// TestPrintScanCoverage_AllSectionsRendered verifies that when all three
// coverage fields are populated, all three sections appear in the output.
func TestPrintScanCoverage_AllSectionsRendered(t *testing.T) {
	pp, read := newTestPrettyPrinterFile(t)

	coverage := cautils.ScanCoverage{
		FailedGVRPulls: []cautils.FailedGVRPull{
			{GVR: "rbac.authorization.k8s.io/v1/clusterroles", Error: "forbidden"},
		},
		NotEvaluatedControls: []cautils.NotEvaluatedControl{
			{ControlID: "C-0001", MissingGVRs: []string{"rbac.authorization.k8s.io/v1/clusterroles"}},
		},
		PartialGVRPulls: []cautils.PartialGVRPull{
			{GVR: "/v1/pods", Selector: "metadata.namespace=prod", Error: "forbidden for prod"},
		},
	}
	pp.printScanCoverage(coverage)

	out := read()
	assert.True(t, strings.Count(out, "Scan Coverage Warning") == 1, "exactly one header")
	assert.Contains(t, out, "clusterroles")
	assert.Contains(t, out, "C-0001")
	assert.Contains(t, out, "/v1/pods")
}

func TestSetWriter_Pretty(t *testing.T) {
	tests := []struct {
		name       string
		outputFile string
		expected   string
	}{
		{
			name:       "Output file name doesn't contain any extension",
			outputFile: "customFilename",
			expected:   "customFilename.txt",
		},
		{
			name:       "Output file name contains .txt",
			outputFile: "customFilename.txt",
			expected:   "customFilename.txt",
		},
		{
			name:       "Output file name is empty",
			outputFile: "",
			expected:   "/dev/stdout",
		},
		{
			name:       "Output file is os.DevNull",
			outputFile: os.DevNull,
			expected:   os.DevNull,
		},
	}

	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pp := NewPrettyPrinter(false, "v2", false, cautils.ViewTypes("control"), cautils.ScanTypes("cluster"), []string{}, "")

			pp.SetWriter(ctx, tt.outputFile)
			assert.Equal(t, tt.expected, pp.writer.Name())
		})
	}
}
