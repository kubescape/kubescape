//go:build unix && !aix && !illumos && !solaris

package getter

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/core/pkg/ruledir"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadWithin runs LoadCustomRules under a deadline: a FIFO with no writer
// blocks a plain open forever, so a regression must not hang the suite.
func loadWithin(t *testing.T, path string) (*reporthandling.Framework, error) {
	t.Helper()

	type result struct {
		fw  *reporthandling.Framework
		err error
	}
	done := make(chan result, 1)
	go func() {
		fw, err := LoadCustomRules(path)
		done <- result{fw, err}
	}()

	select {
	case r := <-done:
		return r.fw, r.err
	case <-time.After(5 * time.Second):
		t.Fatal("LoadCustomRules blocked on a non-regular rule file")
		return nil, nil
	}
}

// A FIFO is opened read-write on cleanup so a goroutine stuck on it is freed.
func mkfifo(t *testing.T, path string) {
	t.Helper()

	require.NoError(t, syscall.Mkfifo(path, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})
}

func TestLoadCustomRules_FIFORegoFileIsRejectedPromptly(t *testing.T) {
	t.Run("bare file", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "pipe.rego")
		mkfifo(t, f)

		_, err := loadWithin(t, f)
		assert.ErrorIs(t, err, ruledir.ErrNotRegularFile)
	})

	t.Run("bare file in a directory", func(t *testing.T) {
		dir := t.TempDir()
		mkfifo(t, filepath.Join(dir, "pipe.rego"))

		_, err := loadWithin(t, dir)
		assert.ErrorIs(t, err, ruledir.ErrNotRegularFile)
	})
}

// A FIFO under a rule file's name keeps the directory from being a rule, so
// what is left is read as bare .rego files.
func TestLoadCustomRules_FIFOInRuleDirIsNotARule(t *testing.T) {
	t.Run("raw.rego is read as a bare file and rejected", func(t *testing.T) {
		dir := writeRuleDir(t, t.TempDir(), "odd", rbacRuleMetadata)
		require.NoError(t, os.Remove(filepath.Join(dir, "raw.rego")))
		mkfifo(t, filepath.Join(dir, "raw.rego"))

		_, err := loadWithin(t, dir)

		assert.ErrorIs(t, err, ruledir.ErrNotRegularFile)
	})

	t.Run("rule.metadata.json leaves raw.rego as a bare rule", func(t *testing.T) {
		dir := writeRuleDir(t, t.TempDir(), "odd", rbacRuleMetadata)
		require.NoError(t, os.Remove(filepath.Join(dir, "rule.metadata.json")))
		mkfifo(t, filepath.Join(dir, "rule.metadata.json"))

		fw, err := loadWithin(t, dir)

		require.NoError(t, err)
		require.Len(t, fw.Controls, 1)
		assert.Equal(t, "custom-raw", fw.Controls[0].ControlID)
	})
}

func TestLoadCustomRules_DeviceRegoFileIsRejectedPromptly(t *testing.T) {
	if _, err := os.Stat("/dev/zero"); err != nil {
		t.Skip("no /dev/zero on this system")
	}
	f := filepath.Join(t.TempDir(), "zero.rego")
	require.NoError(t, os.Symlink("/dev/zero", f))

	_, err := loadWithin(t, f)
	assert.ErrorIs(t, err, ruledir.ErrNotRegularFile)
}
