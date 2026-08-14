package v1

import (
	"context"
	"os"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/httphandler/config"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unsetEnvForTest ensures name is absent from the process environment for the
// duration of the test, restoring whatever value (or absence) it had before.
// Needed because t.Setenv can only set a value, not guarantee absence, and
// defaultScanInfo's KS_SUBMIT handling is presence-sensitive.
func unsetEnvForTest(t *testing.T, name string) {
	t.Helper()
	orig, ok := os.LookupEnv(name)
	require.NoError(t, os.Unsetenv(name))
	t.Cleanup(func() {
		if ok {
			os.Setenv(name, orig)
		} else {
			os.Unsetenv(name)
		}
	})
}

func TestDefaultScanInfo(t *testing.T) {
	// KS_SUBMIT must not leak from the ambient environment (dev machine or CI
	// runner) into this default-value assertion.
	unsetEnvForTest(t, "KS_SUBMIT")

	s := defaultScanInfo()

	assert.Equal(t, "", s.AccountID)
	assert.Equal(t, "v2", s.FormatVersion)
	assert.Equal(t, "json", s.Format)
	assert.Equal(t, "", s.AccessKey)
	assert.False(t, s.HostSensorEnabled.GetBool())
	assert.False(t, s.Local)
	assert.False(t, s.Submit.GetBool())
	assert.Nil(t, s.Submit.Get(), "Submit must not be marked explicitly set by default")
}

func TestDefaultScanInfo_SubmitExplicitlySetFromEnv(t *testing.T) {
	t.Setenv("KS_SUBMIT", "false")

	s := defaultScanInfo()

	assert.False(t, s.Submit.GetBool())
	require.NotNil(t, s.Submit.Get())
}

func TestDefaultScanInfo_KS_SUBMIT_UnparsableValueIgnored(t *testing.T) {
	// Regression test: KS_SUBMIT="" (a common Helm rendering for an unset
	// value) or any other unparsable value must NOT be treated as an
	// explicit opt-out - see https://github.com/kubescape/kubescape/issues/2555.
	for _, v := range []string{"", "yes", "enabled", "no"} {
		t.Run("value="+v, func(t *testing.T) {
			t.Setenv("KS_SUBMIT", v)
			s := defaultScanInfo()
			assert.Nil(t, s.Submit.Get(), "unparsable KS_SUBMIT=%q must not mark Submit as explicitly set", v)
		})
	}
}

func TestDefaultScanInfo_KS_SUBMIT_ParsedValues(t *testing.T) {
	tests := []struct {
		raw  string
		want bool
	}{
		{"true", true},
		{"1", true},
		{"TRUE ", true}, // tolerated: case and surrounding whitespace
		{"false", false},
		{"0", false},
		{" False", false},
	}
	for _, tt := range tests {
		t.Run("value="+tt.raw, func(t *testing.T) {
			t.Setenv("KS_SUBMIT", tt.raw)
			s := defaultScanInfo()
			require.NotNil(t, s.Submit.Get())
			assert.Equal(t, tt.want, s.Submit.GetBool())
		})
	}
}

func TestGetScanCommand(t *testing.T) {
	unsetEnvForTest(t, "KS_SUBMIT")

	req := utilsmetav1.PostScanRequest{
		TargetType: apisv1.KindFramework,
	}
	s, _ := getScanCommand(&req, "abc")
	assert.Equal(t, "", s.AccountID)
	assert.Equal(t, "abc", s.ScanID)
	assert.Equal(t, "v2", s.FormatVersion)
	assert.Equal(t, "json", s.Format)
	assert.Equal(t, "", s.AccessKey)
	assert.False(t, s.HostSensorEnabled.GetBool())
	assert.False(t, s.Local)
	assert.False(t, s.Submit.GetBool())
}

func TestGetScanCommandWithAccessKey(t *testing.T) {
	unsetEnvForTest(t, "KS_SUBMIT")
	config.SetAccessKey("test-123")

	req := utilsmetav1.PostScanRequest{
		TargetType: apisv1.KindFramework,
	}
	s, _ := getScanCommand(&req, "abc")
	assert.Equal(t, "", s.AccountID)
	assert.Equal(t, "abc", s.ScanID)
	assert.Equal(t, "v2", s.FormatVersion)
	assert.Equal(t, "json", s.Format)
	assert.Equal(t, "test-123", s.AccessKey)
	assert.False(t, s.HostSensorEnabled.GetBool())
	assert.False(t, s.Local)
	assert.False(t, s.Submit.GetBool())
}

func TestReadResultsFile(t *testing.T) {
	dir := t.TempDir()

	// Temporarily override OutputDir for tests
	oldOutputDir := OutputDir
	OutputDir = dir
	defer func() { OutputDir = oldOutputDir }()

	validUUID := "123e4567-e89b-12d3-a456-426614174000"
	targetFile := dir + "/" + validUUID + ".json"
	otherFile := dir + "/other-xyz.json"

	err := os.WriteFile(targetFile, []byte("{}"), 0644)
	assert.NoError(t, err)
	err = os.WriteFile(otherFile, []byte("{}"), 0644)
	assert.NoError(t, err)

	// readResultsFile should find the target via exact match
	_, err = readResultsFile(validUUID)
	assert.NoError(t, err)

	// readResultsFile should not find a non-existent UUID
	_, err = readResultsFile("111e4567-e89b-12d3-a456-426614174000")
	assert.ErrorContains(t, err, "file 111e4567-e89b-12d3-a456-426614174000 not found")

	// readResultsFile should reject invalid UUID formats
	_, err = readResultsFile("invalid-uuid")
	assert.ErrorContains(t, err, "invalid scan ID format")

	// readResultsFile should prevent path traversal
	_, err = readResultsFile("../target")
	assert.ErrorContains(t, err, "invalid scan ID format")
}

func TestRemoveResultsFile(t *testing.T) {
	dir := t.TempDir()

	// Temporarily override OutputDir for tests
	oldOutputDir := OutputDir
	OutputDir = dir
	defer func() { OutputDir = oldOutputDir }()

	validUUID := "123e4567-e89b-12d3-a456-426614174000"
	targetFile := dir + "/" + validUUID + ".json"

	err := os.WriteFile(targetFile, []byte("{}"), 0644)
	assert.NoError(t, err)

	// removeResultsFile should succeed
	err = removeResultsFile(validUUID)
	assert.NoError(t, err)
	_, statErr := os.Stat(targetFile)
	assert.True(t, os.IsNotExist(statErr))

	// removeResultsFile should ignore invalid UUID formats
	err = removeResultsFile("invalid-uuid")
	assert.NoError(t, err) // Logs warning, but no error returned

	// removeResultsFile should prevent path traversal
	err = removeResultsFile("../target")
	assert.NoError(t, err)
}

func TestWatchForScan_GracefulShutdown(t *testing.T) {
	h := NewHTTPHandler(false)

	// Shutdown should cause the watchForScan goroutine to exit cleanly.
	h.Shutdown()

	// Verify the handler is still usable for non-scan operations
	// (the scan channel is still there, just no one listening).
	assert.NotNil(t, h.scanRequestChan)
}

func TestWatchForScan_ProcessesRequestThenExits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := &HTTPHandler{
		state:           newServerState(),
		scanRequestChan: make(chan *scanRequestParams, 1),
		cancelWatch:     cancel,
	}

	// Override scanImpl so executeScan returns immediately.
	oldScanImpl := scanImpl
	defer func() { scanImpl = oldScanImpl }()
	scanImpl = func(ctx context.Context, _ *cautils.ScanInfo, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
		return nil, nil
	}

	go h.watchForScan(ctx)

	// Send a scan request — it should be processed.
	h.scanRequestChan <- &scanRequestParams{
		scanID:          "test-shutdown",
		scanInfo:        &cautils.ScanInfo{},
		scanQueryParams: &ScanQueryParams{},
		resp:            make(chan *utilsmetav1.Response, 1),
	}

	// Cancel the context — watchForScan should exit.
	cancel()

	// If watchForScan didn't exit, this test would hang on the send below
	// because no one is reading from the channel. With the fix, the goroutine
	// has exited, so the buffered channel just accumulates.
	h.scanRequestChan <- &scanRequestParams{
		scanID:          "after-shutdown",
		scanInfo:        &cautils.ScanInfo{},
		scanQueryParams: &ScanQueryParams{},
		resp:            make(chan *utilsmetav1.Response, 1),
	}
}
