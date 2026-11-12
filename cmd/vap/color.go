package vap

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
	for i := 0; i < 10 && w != nil; i++ {
		if d, ok := w.(interface{ DisableColor() bool }); ok && d.DisableColor() {
			return false
		}
		if u, ok := w.(interface{ Unwrap() io.Writer }); ok {
			w = u.Unwrap()
		} else {
			break
		}
	}
	if val, set := os.LookupEnv("NO_COLOR"); set && val != "" {
		return false
	}
	if val, set := os.LookupEnv("FORCE_COLOR"); set {
		return val != "0"
	}
	if gchalk.GetLevel() == gchalk.LevelNone {
		return false
	}
	if f, ok := w.(*os.File); ok && f != nil {
		return isTerminal(f.Fd()) || isCygwinTerminal(f.Fd())
	}
	return false
}
