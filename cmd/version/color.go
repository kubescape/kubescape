package version

import (
	"io"
	"os"

	"github.com/jwalton/gchalk"
	"github.com/mattn/go-isatty"
)

var (
	isTerminal       = isatty.IsTerminal
	isCygwinTerminal = isatty.IsCygwinTerminal
)

func shouldColor(w io.Writer) bool {
	if val, set := os.LookupEnv("NO_COLOR"); set && val != "" {
		return false
	}
	if val, set := os.LookupEnv("FORCE_COLOR"); set {
		return val != "0"
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	if f, ok := w.(*os.File); ok && f != nil {
		return isTerminal(f.Fd()) || isCygwinTerminal(f.Fd())
	}
	return false
}

// colorBuilder returns a *gchalk.Builder configured for the requested color state.
// When colored is true, it ensures the builder has an active color level even if
// gchalk's global detection disabled colors at startup due to an empty NO_COLOR="",
// provided the terminal supports virtual-terminal/ANSI sequences.
func colorBuilder(colored bool) *gchalk.Builder {
	if !colored {
		return gchalk.New(gchalk.ForceLevel(gchalk.LevelNone))
	}
	level := gchalk.GetLevel()
	if level <= gchalk.LevelNone && supportsVirtualTerminal() {
		level = gchalk.LevelBasic
	}
	return gchalk.New(gchalk.ForceLevel(level))
}
