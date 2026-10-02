package v1

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
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

	scanErr := errors.New("cannot read /home/user/.kube/config: denied")
	err := writeScanErrorToFile(scanErr, testScanErrID)
	require.Error(t, err)
	// the returned error is copied into the HTTP response, so it must be redacted too
	assert.NotContains(t, err.Error(), "/home/user")
	assert.Equal(t, "failed to scan. reason: cannot read <path>: denied", err.Error())
	assert.ErrorIs(t, err, scanErr)
	got, readErr := os.ReadFile(filepath.Join(FailedOutputDir, testScanErrID))
	require.NoError(t, readErr)
	assert.Equal(t, "cannot read <path>: denied", string(got))

	badIDErr := writeScanErrorToFile(scanErr, "../escape")
	require.Error(t, badIDErr)
	assert.NotContains(t, badIDErr.Error(), "/home/user")
	_, statErr := os.Stat(filepath.Join(tmpDir, "escape"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestRedactScanError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"unix path", errors.New("cannot read /home/alice/.kube/config: denied"), "cannot read <path>: denied"},
		{"unix path with spaces", errors.New("open /home/alice/Team Secrets/config: denied"), "open <path>: denied"},
		{"words after path are kept", errors.New("open /a/b in dir /c/d"), "open <path> in dir <path>"},
		{"windows drive path", errors.New(`open C:\Users\alice\.kube\config: denied`), "open <path>: denied"},
		{"windows drive path with spaces", errors.New(`open C:\Users\alice\Team Secrets\config: denied`), "open <path>: denied"},
		{"windows forward slashes", errors.New("open C:/Users/alice/config: denied"), "open <path>: denied"},
		{"unc path", errors.New(`open \\fileserver\share\alice\config: denied`), "open <path>: denied"},
		{
			"structured path error with spaces in last component",
			fmt.Errorf("load kubeconfig: %w", &fs.PathError{Op: "open", Path: "/home/alice/my config", Err: fs.ErrPermission}),
			"load kubeconfig: open <path>: permission denied",
		},
		{
			"structured windows path error",
			&fs.PathError{Op: "open", Path: `C:\Users\alice\my config`, Err: fs.ErrNotExist},
			"open <path>: file does not exist",
		},
		{"no path", errors.New("scan failed"), "scan failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, redactScanError(tt.err))
		})
	}
}

func TestWriteScanErrorToFile_RedactsPersistedWindowsPaths(t *testing.T) {
	tmpDir := t.TempDir()
	oldFailedOutputDir := FailedOutputDir
	FailedOutputDir = tmpDir
	defer func() { FailedOutputDir = oldFailedOutputDir }()

	err := writeScanErrorToFile(errors.New(`open \\srv\share\Team Secrets\config: denied`), testScanErrID)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "Secrets")
	got, readErr := os.ReadFile(filepath.Join(tmpDir, testScanErrID))
	require.NoError(t, readErr)
	assert.Equal(t, "open <path>: denied", string(got))
}

func TestWriteScanErrorToFile_ChmodFailureWritesNothing(t *testing.T) {
	tmpDir := t.TempDir()
	oldFailedOutputDir := FailedOutputDir
	FailedOutputDir = tmpDir
	defer func() { FailedOutputDir = oldFailedOutputDir }()
	oldChmod := chmodScanErrorFile
	chmodScanErrorFile = func(*os.File, os.FileMode) error { return fs.ErrPermission }
	defer func() { chmodScanErrorFile = oldChmod }()
	target := filepath.Join(tmpDir, testScanErrID)
	require.NoError(t, os.WriteFile(target, []byte("previous error"), 0o600))

	err := writeScanErrorToFile(errors.New("secret details"), testScanErrID)
	require.Error(t, err)
	assert.ErrorContains(t, err, "failed to restrict file permissions")
	got, readErr := os.ReadFile(target)
	require.NoError(t, readErr)
	assert.Equal(t, "previous error", string(got), "the previous file must not be truncated when tightening fails")
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
