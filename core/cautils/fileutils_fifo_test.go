//go:build unix

package cautils

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A FIFO reports size 0 from Stat whatever it carries, so these tests pin
// that loadFiles reads what is actually there instead of trusting the size.

const fifoTestManifest = `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"cm","namespace":"default"}}`

// writeFIFO creates a FIFO at path and feeds data into it once a reader opens
// it. Write errors are ignored: a reader that stops early (as the size limit
// does) closes the pipe under the writer.
func writeFIFO(t *testing.T, path string, data []byte) {
	t.Helper()
	require.NoError(t, syscall.Mkfifo(path, 0o600))

	done := make(chan struct{})
	go func() {
		defer close(done)
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return
		}
		_, _ = f.Write(data)
		_ = f.Close()
	}()
	t.Cleanup(func() {
		// Unblock a writer still waiting for a reader, then wait for it.
		if r, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = r.Close()
		}
		<-done
	})
}

func TestLoadFiles_ReadsManifestFromFIFO(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular.json")
	require.NoError(t, os.WriteFile(regular, []byte(fifoTestManifest), 0o600))
	piped := filepath.Join(dir, "piped.json")
	writeFIFO(t, piped, []byte(fifoTestManifest))

	workloads, skips, errs := loadFiles(dir, []string{regular, piped})
	require.Empty(t, errs)
	require.Empty(t, skips)
	assert.Len(t, workloads[regular], 1)
	assert.Len(t, workloads[piped], 1, "manifest read from a FIFO was dropped")
}

func TestLoadFiles_FIFOOverSizeLimitIsSkipped(t *testing.T) {
	t.Setenv(MaxFileSizeEnvVar, "10")
	dir := t.TempDir()
	piped := filepath.Join(dir, "piped.json")
	writeFIFO(t, piped, []byte("12345678901")) // 11 bytes

	workloads, skips, errs := loadFiles(dir, []string{piped})
	assert.Empty(t, workloads)
	require.Len(t, errs, 1)
	assert.ErrorIs(t, errs[0], ErrFileTooLarge)
	require.Len(t, skips, 1)
	assert.Equal(t, piped, skips[0].Path)
}
