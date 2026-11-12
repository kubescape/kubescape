//go:build unix && !aix && !illumos && !solaris

package k8scveindex

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mkfifo(t *testing.T, path string) {
	t.Helper()

	require.NoError(t, syscall.Mkfifo(path, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})
}

func TestLoad_LocalPathFIFOWithoutWriterRejectedPromptly(t *testing.T) {
	fifoPath := filepath.Join(t.TempDir(), "feed.fifo")
	mkfifo(t, fifoPath)

	type result struct {
		ix  *Index
		src Source
		err error
	}

	done := make(chan result, 1)
	go func() {
		ix, src, err := Load(context.Background(), Options{LocalPath: fifoPath})
		done <- result{ix: ix, src: src, err: err}
	}()

	select {
	case r := <-done:
		assert.Error(t, r.err)
		assert.Nil(t, r.ix)
		assert.Empty(t, r.src)
	case <-time.After(3 * time.Second):
		t.Fatal("Load blocked indefinitely on a FIFO without a writer")
	}
}
