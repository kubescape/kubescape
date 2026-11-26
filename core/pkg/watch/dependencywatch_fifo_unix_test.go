//go:build unix

package watch

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestLoadHelmIgnoreRules_RejectsFIFOWithoutBlocking(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)

	t.Run("direct FIFO fails fast", func(t *testing.T) {
		fifo := filepath.Join(dir, ".helmignore-direct")
		require.NoError(t, unix.Mkfifo(fifo, 0o600))

		done := make(chan error, 1)
		go func() {
			_, err := loadHelmIgnoreRules(fifo)
			done <- err
		}()

		select {
		case err := <-done:
			require.ErrorIs(t, err, errHelmIgnoreNotRegular)
		case <-time.After(2 * time.Second):
			if f, err := os.OpenFile(fifo, os.O_RDWR|unix.O_NONBLOCK, 0); err == nil {
				_ = f.Close()
			}
			t.Fatal("loadHelmIgnoreRules blocked on FIFO")
		}
	})

	t.Run("symlink to FIFO fails fast in addChart", func(t *testing.T) {
		chart := filepath.Join(dir, "chart")
		git := filepath.Join(chart, ".git")
		write(t, filepath.Join(git, "settings"), "chart data")

		fifo := filepath.Join(dir, "ignore-pipe")
		require.NoError(t, unix.Mkfifo(fifo, 0o600))
		require.NoError(t, os.Symlink(fifo, filepath.Join(chart, ".helmignore")))

		done := make(chan dependencyDirectories, 1)
		go func() {
			plan := make(dependencyDirectories)
			plan.addChart(t.Context(), chart, make(map[string]struct{}))
			done <- plan
		}()

		select {
		case plan := <-done:
			require.Contains(t, plan, git)
			require.True(t, plan[git].chart)
		case <-time.After(2 * time.Second):
			if f, err := os.OpenFile(fifo, os.O_RDWR|unix.O_NONBLOCK, 0); err == nil {
				_ = f.Close()
			}
			t.Fatal("addChart blocked on FIFO .helmignore symlink")
		}
	})
}
