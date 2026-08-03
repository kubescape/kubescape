package v1

import (
	"errors"
	"os"
	"path/filepath"
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

// TestWriteScanErrorToFile_CreatesDirectoryWithRestrictivePermissions guards
// against a regression back to os.ModePerm (0777, world-writable) for
// FailedOutputDir. FailedOutputDir must not already exist for this to
// exercise the MkdirAll call - t.TempDir() itself always exists, so this
// nests one level under it.
func TestWriteScanErrorToFile_CreatesDirectoryWithRestrictivePermissions(t *testing.T) {
	nested := filepath.Join(t.TempDir(), "failed")
	oldFailedOutputDir := FailedOutputDir
	FailedOutputDir = nested
	defer func() { FailedOutputDir = oldFailedOutputDir }()

	require.Error(t, writeScanErrorToFile(errors.New("scan failed"), "scan-id"))

	info, err := os.Stat(nested)
	require.NoError(t, err)
	mode := info.Mode().Perm()
	assert.Zerof(t, mode&0o027, "directory %s has mode %o, more permissive than 0750", nested, mode)
}
