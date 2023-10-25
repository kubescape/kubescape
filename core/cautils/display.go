package cautils

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	spinnerpkg "github.com/briandowns/spinner"
	"github.com/jwalton/gchalk"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/mattn/go-isatty"
	"github.com/schollz/progressbar/v3"
)

func FailureDisplay(w io.Writer, format string, a ...interface{}) {
	fmt.Fprintf(w, gchalk.WithBrightRed().Bold(format), a...)
}

func WarningDisplay(w io.Writer, format string, a ...interface{}) {
	fmt.Fprintf(w, gchalk.WithBrightYellow().Bold(format), a...)
}

func FailureTextDisplay(w io.Writer, format string, a ...interface{}) {
	fmt.Fprintf(w, gchalk.WithBrightRed().Dim(format), a...)
}

func InfoDisplay(w io.Writer, format string, a ...interface{}) {
	fmt.Fprintf(w, gchalk.WithBrightWhite().Bold(format), a...)
}

func InfoTextDisplay(w io.Writer, format string, a ...interface{}) {
	fmt.Fprintf(w, gchalk.WithBrightYellow().Bold(format), a...)
}

func SimpleDisplay(w io.Writer, format string, a ...interface{}) {
	fmt.Fprintf(w, gchalk.White(format), a...)
}

func SuccessDisplay(w io.Writer, format string, a ...interface{}) {
	fmt.Fprintf(w, gchalk.WithBlue().Bold(format), a...)
}

func DescriptionDisplay(w io.Writer, format string, a ...interface{}) {
	fmt.Fprintf(w, gchalk.WithWhite().Dim(format), a...)
}

func BoldDisplay(w io.Writer, format string, a ...interface{}) {
	fmt.Fprintf(w, gchalk.Bold(format), a...)
}

func LineDisplay(w io.Writer, format string, a ...interface{}) {
	fmt.Fprintf(w, gchalk.WithAnsi256(238).Bold(format), a...)
}

func SectionHeadingDisplay(w io.Writer, format string, a ...interface{}) {
	fmt.Fprintf(w, "\n"+
		gchalk.WithBrightWhite().Bold(format)+
		gchalk.WithAnsi256(238).Bold(fmt.Sprintf("\n%s\n\n", strings.Repeat("─", len(format)))), a...)
}

func StarDisplay(w io.Writer, format string, a ...interface{}) {
	fmt.Fprintf(w, gchalk.WithAnsi256(238).Bold("* ")+gchalk.White(format), a...)
}

var spinner *spinnerpkg.Spinner

func StartSpinner() {
	if helpers.ToLevel(logger.L().GetLevel()) >= helpers.WarningLevel {
		return
	}

	if spinner != nil {
		if !spinner.Active() {
			spinner.Start()
		}
		return
	}
	if isatty.IsTerminal(os.Stdout.Fd()) {
		spinner = spinnerpkg.New(spinnerpkg.CharSets[7], 100*time.Millisecond) // Build our new spinner
		spinner.Start()
	}
}

func StopSpinner() {
	if spinner == nil || !spinner.Active() {
		return
	}
	spinner.Stop()
}

type ProgressHandler struct {
	pb    *progressbar.ProgressBar
	title string
}

func NewProgressHandler(title string) *ProgressHandler {
	return &ProgressHandler{title: title}
}

func (p *ProgressHandler) Start(allSteps int) {
	if !isatty.IsTerminal(os.Stderr.Fd()) || helpers.ToLevel(logger.L().GetLevel()) >= helpers.WarningLevel {
		p.pb = progressbar.DefaultSilent(int64(allSteps), p.title)
		return
	}
	p.pb = progressbar.Default(int64(allSteps), p.title)
}

func (p *ProgressHandler) ProgressJob(step int, message string) {
	p.pb.Add(step)
	p.pb.Describe(message)
}

func (p *ProgressHandler) Stop() {
}
