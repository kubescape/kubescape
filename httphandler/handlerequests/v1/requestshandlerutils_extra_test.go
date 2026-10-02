package v1

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
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
	t.Run("valid response marshals successfully", func(t *testing.T) {
		got := responseToBytes(&utilsmetav1.Response{
			Type:     "done",
			Response: "ok",
		})

		assert.JSONEq(t, `{"id":"","type":"done","response":"ok"}`, string(got))
	})

	t.Run("marshal error returns fallback JSON", func(t *testing.T) {
		// A channel cannot be marshaled to JSON, triggering the error path.
		got := responseToBytes(&utilsmetav1.Response{
			Response: make(chan int),
		})

		assert.NotEmpty(t, got)

		var decoded utilsmetav1.Response
		err := json.Unmarshal(got, &decoded)
		assert.NoError(t, err)
		assert.Contains(t, decoded.Response, "failed to marshal response")
	})
}

const testScanErrID = "11111111-1111-1111-1111-111111111111"

func TestWriteScanErrorToFile_RedactsPathsAndRejectsBadID(t *testing.T) {
	tmpDir := t.TempDir()
	oldFailedOutputDir := FailedOutputDir
	FailedOutputDir = filepath.Join(tmpDir, "failed")
	defer func() { FailedOutputDir = oldFailedOutputDir }()

	err := writeScanErrorToFile(errors.New("cannot read /home/user/.kube/config: denied"), testScanErrID)
	require.Error(t, err)
	assert.ErrorContains(t, err, "/home/user/.kube/config")
	got, readErr := os.ReadFile(filepath.Join(FailedOutputDir, testScanErrID))
	require.NoError(t, readErr)
	assert.Equal(t, "cannot read <path>: denied", string(got))

	require.Error(t, writeScanErrorToFile(errors.New("x"), "../escape"))
	_, statErr := os.Stat(filepath.Join(tmpDir, "escape"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestWriteScanErrorToFile(t *testing.T) {
	tmpDir := t.TempDir()
	oldFailedOutputDir := FailedOutputDir
	FailedOutputDir = tmpDir
	defer func() { FailedOutputDir = oldFailedOutputDir }()

	target := filepath.Join(tmpDir, testScanErrID)
	// a pre-existing world-readable file must be tightened to 0600
	require.NoError(t, os.WriteFile(target, []byte("old"), 0o600))
	require.NoError(t, os.Chmod(target, 0o644))

	err := writeScanErrorToFile(errors.New("scan failed"), testScanErrID)

	require.Error(t, err)
	assert.ErrorContains(t, err, "failed to scan. reason: scan failed")
	got, readErr := os.ReadFile(target)
	require.NoError(t, readErr)
	assert.Equal(t, "scan failed", string(got))

	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(target)
		require.NoError(t, statErr)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

// TestWriteScanErrorToFile_CreatesDirectoryWithRestrictivePermissions guards
// against a regression back to os.ModePerm (0777, world-writable) for
// FailedOutputDir. FailedOutputDir must not already exist for this to
// exercise the MkdirAll call - t.TempDir() itself always exists, so this
// nests one level under it.
func TestWriteScanErrorToFile_CreatesDirectoryWithRestrictivePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping directory permission test on Windows")
	}
	nested := filepath.Join(t.TempDir(), "failed")
	oldFailedOutputDir := FailedOutputDir
	FailedOutputDir = nested
	defer func() { FailedOutputDir = oldFailedOutputDir }()

	require.Error(t, writeScanErrorToFile(errors.New("scan failed"), testScanErrID))

	info, err := os.Stat(nested)
	require.NoError(t, err)
	mode := info.Mode().Perm()
	assert.Zerof(t, mode&0o027, "directory %s has mode %o, more permissive than 0750", nested, mode)
}
