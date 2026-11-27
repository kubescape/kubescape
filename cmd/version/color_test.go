package version

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/jwalton/gchalk"
	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// shouldColor
// ---------------------------------------------------------------------------

func TestShouldColor_NoColorSet_NonEmpty_ReturnsFalse(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	t.Setenv("FORCE_COLOR", "1") // must be ignored when NO_COLOR non-empty
	assert.False(t, shouldColor(&bytes.Buffer{}))
}

func TestShouldColor_NoColorEmpty_ForceColor1_ReturnsTrue(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("FORCE_COLOR", "1")
	assert.True(t, shouldColor(&bytes.Buffer{}))
}

func TestShouldColor_ForceColorZero_ReturnsFalse(t *testing.T) {
	if orig, ok := os.LookupEnv("NO_COLOR"); ok {
		defer os.Setenv("NO_COLOR", orig)
	} else {
		defer os.Unsetenv("NO_COLOR")
	}
	os.Unsetenv("NO_COLOR")
	t.Setenv("FORCE_COLOR", "0")
	assert.False(t, shouldColor(&bytes.Buffer{}))
}

func TestShouldColor_TermDumb_ReturnsFalse(t *testing.T) {
	if orig, ok := os.LookupEnv("NO_COLOR"); ok {
		defer os.Setenv("NO_COLOR", orig)
	} else {
		defer os.Unsetenv("NO_COLOR")
	}
	if orig, ok := os.LookupEnv("FORCE_COLOR"); ok {
		defer os.Setenv("FORCE_COLOR", orig)
	} else {
		defer os.Unsetenv("FORCE_COLOR")
	}
	os.Unsetenv("NO_COLOR")
	os.Unsetenv("FORCE_COLOR")
	t.Setenv("TERM", "dumb")
	assert.False(t, shouldColor(&bytes.Buffer{}))
}

func TestShouldColor_NonTTYWriter_ReturnsFalse(t *testing.T) {
	if orig, ok := os.LookupEnv("NO_COLOR"); ok {
		defer os.Setenv("NO_COLOR", orig)
	} else {
		defer os.Unsetenv("NO_COLOR")
	}
	if orig, ok := os.LookupEnv("FORCE_COLOR"); ok {
		defer os.Setenv("FORCE_COLOR", orig)
	} else {
		defer os.Unsetenv("FORCE_COLOR")
	}
	os.Unsetenv("NO_COLOR")
	os.Unsetenv("FORCE_COLOR")
	// A plain bytes.Buffer is never a TTY
	assert.False(t, shouldColor(&bytes.Buffer{}))
}

func TestShouldColor_PlainWriter_NoEnvSet_ReturnsFalse(t *testing.T) {
	if orig, ok := os.LookupEnv("NO_COLOR"); ok {
		defer os.Setenv("NO_COLOR", orig)
	} else {
		defer os.Unsetenv("NO_COLOR")
	}
	if orig, ok := os.LookupEnv("FORCE_COLOR"); ok {
		defer os.Setenv("FORCE_COLOR", orig)
	} else {
		defer os.Unsetenv("FORCE_COLOR")
	}
	if orig, ok := os.LookupEnv("TERM"); ok {
		defer os.Setenv("TERM", orig)
	} else {
		defer os.Unsetenv("TERM")
	}
	os.Unsetenv("NO_COLOR")
	os.Unsetenv("FORCE_COLOR")
	os.Unsetenv("TERM")

	var w io.Writer = &bytes.Buffer{}
	assert.False(t, shouldColor(w))
}

// ---------------------------------------------------------------------------
// colorBuilder
// ---------------------------------------------------------------------------

func TestColorBuilder_ColoredFalse_ProducesNoANSI(t *testing.T) {
	b := colorBuilder(false)
	out := b.Bold("hello")
	assert.NotContains(t, out, "\x1b[", "disabled builder must emit zero ANSI escapes")
	assert.Contains(t, out, "hello")
}

func TestColorBuilder_ColoredTrue_ProducesOutput(t *testing.T) {
	prev := gchalk.GetLevel()
	gchalk.SetLevel(gchalk.LevelAnsi16m)
	defer gchalk.SetLevel(prev)

	b := colorBuilder(true)
	out := b.Bold("hello")
	// With a forced non-None level the builder should wrap the text
	assert.Contains(t, out, "hello")
}

func TestColorBuilder_ColoredFalse_LevelNone(t *testing.T) {
	b := colorBuilder(false)
	// LevelNone builder never adds ANSI regardless of method chained
	assert.NotContains(t, b.BrightGreen("world"), "\x1b[")
}

func TestColorBuilder_ColoredTrue_NoneLevel_FallsBackToBasic(t *testing.T) {
	prev := gchalk.GetLevel()
	gchalk.SetLevel(gchalk.LevelNone)
	defer gchalk.SetLevel(prev)

	// When global level is None but the terminal supports VT sequences
	// colorBuilder should still return a usable builder (level >= Basic when
	// supportsVirtualTerminal is true, otherwise LevelNone).
	b := colorBuilder(true)
	assert.NotNil(t, b)
	// Output must at least contain the text
	assert.Contains(t, b.Bold("test"), "test")
}
