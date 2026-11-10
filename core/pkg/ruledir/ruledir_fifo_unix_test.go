//go:build unix && !aix && !illumos && !solaris

package ruledir

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// within fails the test if fn does not return in time: a FIFO with no writer
// blocks a plain open forever, so a regression must not hang the suite.
func within(t *testing.T, fn func()) {
	t.Helper()

	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("blocked reading a non-regular rule file")
	}
}

// replaceWithFIFO swaps the rule file name in dir for a FIFO with no writer.
// The FIFO is opened read-write on cleanup so a goroutine stuck on it is freed.
func replaceWithFIFO(t *testing.T, dir, name string) {
	t.Helper()

	path := filepath.Join(dir, name)
	require.NoError(t, os.Remove(path))
	require.NoError(t, syscall.Mkfifo(path, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})
}

func TestFIFORuleFilesAreRejectedPromptly(t *testing.T) {
	for _, name := range []string{RegoFileName, MetadataFileName} {
		t.Run(name, func(t *testing.T) {
			dir := completeRule(t, t.TempDir(), "rule")
			replaceWithFIFO(t, dir, name)

			within(t, func() {
				assert.False(t, Is(dir))

				_, err := ReadFile(filepath.Join(dir, name))
				assert.ErrorIs(t, err, ErrNotRegularFile)

				_, ok, err := Load(dir)
				assert.NoError(t, err)
				assert.False(t, ok)
			})
		})
	}
}

func TestDeviceRuleFileIsRejectedPromptly(t *testing.T) {
	if _, err := os.Stat("/dev/zero"); err != nil {
		t.Skip("no /dev/zero on this system")
	}

	dir := completeRule(t, t.TempDir(), "rule")
	require.NoError(t, os.Remove(filepath.Join(dir, RegoFileName)))
	require.NoError(t, os.Symlink("/dev/zero", filepath.Join(dir, RegoFileName)))

	within(t, func() {
		assert.False(t, Is(dir))

		_, err := ReadFile(filepath.Join(dir, RegoFileName))
		assert.ErrorIs(t, err, ErrNotRegularFile)
	})
}
