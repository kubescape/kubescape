package cautils

import (
	"os"
	"time"

	"github.com/briandowns/spinner"
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

var Spinner *spinner.Spinner

func StartSpinner() {
	if isatty.IsTerminal(os.Stdout.Fd()) {
		Spinner = spinner.New(spinner.CharSets[7], 100*time.Millisecond) // Build our new spinner
		Spinner.Start()
	}
}

func StopSpinner() {
	if Spinner == nil {
		return
	}
	Spinner.Stop()
}
