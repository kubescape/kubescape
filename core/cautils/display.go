package cautils

import (
	"os"
	"time"

	spinnerpkg "github.com/briandowns/spinner"
	"github.com/fatih/color"
	"github.com/mattn/go-isatty"
)

var FailureDisplay = color.New(color.Bold, color.FgHiRed).FprintfFunc()
var WarningDisplay = color.New(color.Bold, color.FgHiYellow).FprintfFunc()
var FailureTextDisplay = color.New(color.Faint, color.FgHiRed).FprintfFunc()
var InfoDisplay = color.New(color.Bold, color.FgCyan).FprintfFunc()
var InfoTextDisplay = color.New(color.Bold, color.FgHiYellow).FprintfFunc()
var SimpleDisplay = color.New().FprintfFunc()
var SuccessDisplay = color.New(color.Bold, color.FgHiGreen).FprintfFunc()
var DescriptionDisplay = color.New(color.Faint, color.FgWhite).FprintfFunc()

var spinner *spinnerpkg.Spinner

func StartSpinner() {
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
