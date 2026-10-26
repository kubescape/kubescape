package policy

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
	if _, set := os.LookupEnv("NO_COLOR"); set {
		return false
	}
	if gchalk.GetLevel() == gchalk.LevelNone {
		return false
	}
	if val, set := os.LookupEnv("FORCE_COLOR"); set {
		return val != "0"
	}
	if f, ok := w.(*os.File); ok {
		return isTerminal(f.Fd()) || isCygwinTerminal(f.Fd())
	}
	return false
}
