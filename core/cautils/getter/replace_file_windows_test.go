//go:build windows

package getter

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestSaveInFileReplacesFileHeldOpenBriefly(t *testing.T) {
	target := filepath.Join(t.TempDir(), "policy.json")
	require.NoError(t, SaveInFile(map[string]string{"v": "old"}, target))

	reader, err := os.Open(target)
	require.NoError(t, err)
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = reader.Close()
	}()

	require.NoError(t, SaveInFile(map[string]string{"v": "new"}, target))

	data, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Contains(t, string(data), "new")
}

func TestSaveInFileGivesUpWhenFileStaysOpen(t *testing.T) {
	target := filepath.Join(t.TempDir(), "policy.json")
	require.NoError(t, SaveInFile(map[string]string{"v": "old"}, target))

	reader, err := os.Open(target)
	require.NoError(t, err)
	defer reader.Close()

	require.Error(t, SaveInFile(map[string]string{"v": "new"}, target))

	data, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Contains(t, string(data), "old")
}

// openExclusive opens path with no sharing, so any other open fails with a
// sharing violation until the handle is closed.
func openExclusive(t *testing.T, path string) windows.Handle {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	require.NoError(t, err)
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, 0, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	require.NoError(t, err)
	return handle
}

func TestReadPolicyFileWaitsForBrieflyLockedFile(t *testing.T) {
	target := filepath.Join(t.TempDir(), "policy.json")
	require.NoError(t, SaveInFile(map[string]string{"v": "old"}, target))

	handle := openExclusive(t, target)
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = windows.CloseHandle(handle)
	}()

	data, err := readPolicyFile(target)
	require.NoError(t, err)
	require.Contains(t, string(data), "old")
}

func TestReadPolicyFileGivesUpWhenFileStaysLocked(t *testing.T) {
	target := filepath.Join(t.TempDir(), "policy.json")
	require.NoError(t, SaveInFile(map[string]string{"v": "old"}, target))

	handle := openExclusive(t, target)
	defer func() { _ = windows.CloseHandle(handle) }()

	_, err := readPolicyFile(target)
	require.ErrorIs(t, err, windows.ERROR_SHARING_VIOLATION)
}
