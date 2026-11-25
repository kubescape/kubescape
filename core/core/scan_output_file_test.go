package core

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const previousReport = `{"previous":"report that is much longer than anything a tiny failed scan would write, ............................."}`

// A scan that fails before it has a report must leave an existing --output
// file as it was, instead of truncating it to 0 bytes.
func TestScan_FailedScanKeepsExistingOutputFile(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		name := "eager"
		if streaming {
			name = "streaming"
		}
		t.Run(name, func(t *testing.T) {
			scanInfo, policyIdentifiers, _ := buildBrokenRuleScanInfo(t)
			// A scan-level error: no control is left to scan.
			scanInfo.IncludeControls = "C-DOES-NOT-EXIST"
			scanInfo.EnableStreaming = streaming
			scanInfo.Format = "json"
			scanInfo.Output = filepath.Join(t.TempDir(), "report.json")
			require.NoError(t, os.WriteFile(scanInfo.Output, []byte(previousReport), 0o600))

			ks := NewKubescape(context.Background())
			_, err := ks.ScanContext(context.Background(), scanInfo, policyIdentifiers)
			require.Error(t, err)

			got, readErr := os.ReadFile(scanInfo.Output)
			require.NoError(t, readErr)
			assert.Equal(t, previousReport, string(got))
		})
	}
}

// A failed scan must not leave an empty file behind at a path that did not
// exist before it.
func TestScan_FailedScanDoesNotLeaveANewOutputFile(t *testing.T) {
	scanInfo, policyIdentifiers, _ := buildBrokenRuleScanInfo(t)
	scanInfo.IncludeControls = "C-DOES-NOT-EXIST"
	scanInfo.Format = "json"
	scanInfo.Output = filepath.Join(t.TempDir(), "report.json")

	ks := NewKubescape(context.Background())
	_, err := ks.ScanContext(context.Background(), scanInfo, policyIdentifiers)
	require.Error(t, err)

	assert.NoFileExists(t, scanInfo.Output)
}

// A scan that succeeds still replaces the whole file: no bytes of a longer
// previous report may remain after the new one.
func TestScan_SuccessfulScanFullyReplacesExistingOutputFile(t *testing.T) {
	scanInfo, policyIdentifiers, _ := buildBrokenRuleScanInfo(t)
	scanInfo.Format = "json"
	scanInfo.Output = filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, os.WriteFile(scanInfo.Output, []byte(previousReport+previousReport+previousReport), 0o600))

	ks := NewKubescape(context.Background())
	results, err := ks.ScanContext(context.Background(), scanInfo, policyIdentifiers)
	require.NoError(t, err)
	require.NoError(t, results.HandleResults(context.Background(), scanInfo))

	got, readErr := os.ReadFile(scanInfo.Output)
	require.NoError(t, readErr)
	require.True(t, json.Valid(got), "the new report must be a complete JSON document with nothing left over")
	assert.NotContains(t, string(got), "previous")
}
