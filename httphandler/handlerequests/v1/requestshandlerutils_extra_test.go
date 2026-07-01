package v1

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvHelpers(t *testing.T) {
	t.Run("envToString returns default when unset", func(t *testing.T) {
		t.Setenv("KS_TEST_STRING", "")
		require.NoError(t, os.Unsetenv("KS_TEST_STRING"))

		assert.Equal(t, "fallback", envToString("KS_TEST_STRING", "fallback"))
	})

	t.Run("envToString returns configured value", func(t *testing.T) {
		t.Setenv("KS_TEST_STRING", "configured")

		assert.Equal(t, "configured", envToString("KS_TEST_STRING", "fallback"))
	})

	t.Run("envToBool returns default when unset", func(t *testing.T) {
		t.Setenv("KS_TEST_BOOL", "")
		require.NoError(t, os.Unsetenv("KS_TEST_BOOL"))

		assert.True(t, envToBool("KS_TEST_BOOL", true))
	})

	t.Run("envToBool parses configured value", func(t *testing.T) {
		t.Setenv("KS_TEST_BOOL", "true")

		assert.True(t, envToBool("KS_TEST_BOOL", false))
	})
}

func TestResponseToBytes(t *testing.T) {
	got := responseToBytes(&utilsmetav1.Response{
		Type:     "done",
		Response: "ok",
	})

	assert.JSONEq(t, `{"id":"","type":"done","response":"ok"}`, string(got))
}

func TestWriteScanErrorToFile(t *testing.T) {
	tmpDir := t.TempDir()
	oldFailedOutputDir := FailedOutputDir
	FailedOutputDir = tmpDir
	defer func() { FailedOutputDir = oldFailedOutputDir }()

	err := writeScanErrorToFile(errors.New("scan failed"), "scan-id")

	require.Error(t, err)
	assert.ErrorContains(t, err, "failed to scan. reason: 'scan failed'")
	got, readErr := os.ReadFile(filepath.Join(tmpDir, "scan-id"))
	require.NoError(t, readErr)
	assert.Equal(t, "scan failed", string(got))
}

// TestExecuteScan_SubmissionFailureIsNonFatal verifies that when scanImpl returns
// nil (no error) — which is now the case when HandleResults fails only due to
// a backend submission error — the executeScan path does NOT write a failed
// artifact to FailedOutputDir.
//
// This is the key invariant for the offline/self-hosted fix (issue #2449):
// ARMO backend submission failures must not prevent in-cluster CRD persistence.
// Before the fix, a HandleResults error caused writeScanErrorToFile to be called,
// which wrote a failed artifact and caused the scan to be reported as failed,
// preventing StorePostureReportResults from ever running.
func TestExecuteScan_SubmissionFailureIsNonFatal(t *testing.T) {
	dir := t.TempDir()

	oldFailedOutputDir := FailedOutputDir
	FailedOutputDir = filepath.Join(dir, "failed")
	defer func() { FailedOutputDir = oldFailedOutputDir }()
	require.NoError(t, os.MkdirAll(FailedOutputDir, 0o755))

	// Restore the real scanImpl after the test.
	defer func(o scanner) { scanImpl = o }(scanImpl)

	scanID := "11111111-2222-3333-4444-555555555555"

	// After the fix, scan() returns (nil, nil) even when HandleResults fails
	// with a submission error, because submission errors are non-fatal.
	scanImpl = func(_ context.Context, _ *cautils.ScanInfo, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
		return nil, nil
	}

	h := NewHTTPHandler(false)
	resp := make(chan *utilsmetav1.Response, 1)
	scanReq := &scanRequestParams{
		ctx:      context.Background(),
		scanInfo: &cautils.ScanInfo{},
		scanID:   scanID,
		scanQueryParams: &ScanQueryParams{
			ReturnResults: true,
		},
		resp: resp,
	}
	h.state.setBusy(scanID)
	h.executeScan(scanReq)

	// No failed artifact should exist: a submission-only failure must not
	// pollute FailedOutputDir and must not block in-cluster CRD persistence.
	_, err := os.Stat(filepath.Join(FailedOutputDir, scanID))
	assert.True(t, os.IsNotExist(err),
		"a submission-only failure must not write a failed artifact to FailedOutputDir "+
			"(this would block StorePostureReportResults and prevent WorkloadConfigurationScan creation)")
}
