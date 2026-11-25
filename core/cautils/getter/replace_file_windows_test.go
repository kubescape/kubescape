//go:build windows

package getter

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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
