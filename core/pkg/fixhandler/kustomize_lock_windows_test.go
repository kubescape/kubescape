//go:build windows

package fixhandler

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWindowsLock_RejectsReparsePoint(t *testing.T) {
	t.Run("file symlink", func(t *testing.T) {
		outDir := t.TempDir()
		outsideDir := t.TempDir()
		externalTarget := filepath.Join(outsideDir, "external-created.txt")
		require.NoFileExists(t, externalTarget)

		lockPath := filepath.Join(outDir, ".kust.lock")
		if err := os.Symlink(externalTarget, lockPath); err != nil {
			t.Skipf("file symlink creation requires privileges: %v", err)
		}
		assertLockRejectsReparsePoint(t, lockPath, externalTarget)
	})

	t.Run("directory junction", func(t *testing.T) {
		outDir := t.TempDir()
		outsideDir := t.TempDir()
		externalTarget := filepath.Join(outsideDir, "external-created.txt")
		require.NoFileExists(t, externalTarget)

		lockPath := filepath.Join(outDir, ".kust.lock")
		outsideTargetDir := filepath.Join(outsideDir, "external-junction-target")
		require.NoError(t, os.MkdirAll(outsideTargetDir, 0700))
		cmd := exec.Command("cmd.exe", "/c", "mklink", "/J", lockPath, outsideTargetDir)
		if cmdErr := cmd.Run(); cmdErr != nil {
			t.Fatalf("failed to create directory junction: %v", cmdErr)
		}
		assertLockRejectsReparsePoint(t, lockPath, externalTarget)
	})
}

func assertLockRejectsReparsePoint(t *testing.T, lockPath, externalTarget string) {
	t.Helper()
	lock, err := newKustomizeLock(lockPath)
	require.NoError(t, err)

	locked, err := lock.TryLock()
	require.Error(t, err, "TryLock on a reparse point must fail")
	assert.False(t, locked)
	assert.NoFileExists(t, externalTarget, "target outside output directory must not be created")
}

func TestWindowsLock_LockAndUnlock(t *testing.T) {
	outDir := t.TempDir()
	lockPath := filepath.Join(outDir, ".kust.lock")

	lock1, err := newKustomizeLock(lockPath)
	require.NoError(t, err)

	locked, err := lock1.TryLock()
	require.NoError(t, err)
	require.True(t, locked)

	// Second lock attempt on the same file should report locked=false without error
	lock2, err := newKustomizeLock(lockPath)
	require.NoError(t, err)

	locked2, err := lock2.TryLock()
	require.NoError(t, err)
	assert.False(t, locked2, "second lock attempt should not acquire exclusive lock")

	// Release lock1
	require.NoError(t, lock1.Unlock())

	// Now lock2 should be able to acquire the lock
	locked2Retry, err := lock2.TryLock()
	require.NoError(t, err)
	assert.True(t, locked2Retry, "lock should be acquirable after unlock")
	require.NoError(t, lock2.Unlock())
}
