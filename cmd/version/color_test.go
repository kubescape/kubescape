package version

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func unsetColorEnvForTest(t *testing.T, key string) {
	t.Helper()
	orig, existed := os.LookupEnv(key)
	require.NoError(t, os.Unsetenv(key))
	t.Cleanup(func() {
		if existed {
			_ = os.Setenv(key, orig)
		} else {
			_ = os.Unsetenv(key)
		}
	})
}

func TestShouldColor(t *testing.T) {
	origIsTerminal := isTerminal
	origIsCygwin := isCygwinTerminal
	t.Cleanup(func() {
		isTerminal = origIsTerminal
		isCygwinTerminal = origIsCygwin
	})

	clearColorEnv := func(t *testing.T) {
		t.Helper()
		unsetColorEnvForTest(t, "NO_COLOR")
		unsetColorEnvForTest(t, "FORCE_COLOR")
		unsetColorEnvForTest(t, "TERM")
	}

	t.Run("non-empty NO_COLOR disables color even when FORCE_COLOR is set", func(t *testing.T) {
		clearColorEnv(t)
		t.Setenv("NO_COLOR", "1")
		t.Setenv("FORCE_COLOR", "1")

		assert.False(t, shouldColor(&bytes.Buffer{}))
	})

	t.Run("empty NO_COLOR does not block FORCE_COLOR", func(t *testing.T) {
		clearColorEnv(t)
		t.Setenv("NO_COLOR", "")
		t.Setenv("FORCE_COLOR", "1")

		assert.True(t, shouldColor(&bytes.Buffer{}))
	})

	t.Run("FORCE_COLOR=0 disables color even on terminal file", func(t *testing.T) {
		clearColorEnv(t)
		t.Setenv("FORCE_COLOR", "0")
		isTerminal = func(uintptr) bool { return true }
		isCygwinTerminal = func(uintptr) bool { return false }

		f, err := os.CreateTemp(t.TempDir(), "tty-*")
		require.NoError(t, err)
		t.Cleanup(func() { _ = f.Close() })

		assert.False(t, shouldColor(f))
	})

	t.Run("TERM=dumb disables color", func(t *testing.T) {
		clearColorEnv(t)
		t.Setenv("TERM", "dumb")
		isTerminal = func(uintptr) bool { return true }
		isCygwinTerminal = func(uintptr) bool { return false }

		f, err := os.CreateTemp(t.TempDir(), "tty-*")
		require.NoError(t, err)
		t.Cleanup(func() { _ = f.Close() })

		assert.False(t, shouldColor(f))
	})

	t.Run("non-file writer and typed nil file return false", func(t *testing.T) {
		clearColorEnv(t)
		isTerminal = func(uintptr) bool { return true }
		isCygwinTerminal = func(uintptr) bool { return true }

		assert.False(t, shouldColor(&bytes.Buffer{}))
		var nilFile *os.File
		assert.False(t, shouldColor(nilFile))
	})

	t.Run("file writer delegates to terminal detectors", func(t *testing.T) {
		clearColorEnv(t)
		f, err := os.CreateTemp(t.TempDir(), "tty-*")
		require.NoError(t, err)
		t.Cleanup(func() { _ = f.Close() })

		isTerminal = func(uintptr) bool { return true }
		isCygwinTerminal = func(uintptr) bool { return false }
		assert.True(t, shouldColor(f))

		isTerminal = func(uintptr) bool { return false }
		isCygwinTerminal = func(uintptr) bool { return true }
		assert.True(t, shouldColor(f))

		isTerminal = func(uintptr) bool { return false }
		isCygwinTerminal = func(uintptr) bool { return false }
		assert.False(t, shouldColor(f))
	})
}

func TestColorBuilder(t *testing.T) {
	t.Run("uncolored builder emits plain text without ANSI escapes", func(t *testing.T) {
		b := colorBuilder(false)
		require.NotNil(t, b)
		assert.Equal(t, "v4.0.0", b.Green("v4.0.0"))
	})

	t.Run("colored builder returns usable builder", func(t *testing.T) {
		b := colorBuilder(true)
		require.NotNil(t, b)
		assert.Contains(t, b.Green("v4.0.0"), "v4.0.0")
	})
}
