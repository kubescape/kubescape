package cautils

import (
	"fmt"
	"os"
	"time"

	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	"github.com/mattn/go-isatty"
)

var silent = false

func SetSilentMode(s bool) {
	silent = s
}

func IsSilent() bool {
	return silent
}

var FailureDisplay = color.New(color.Bold, color.FgHiRed).FprintfFunc()
var WarningDisplay = color.New(color.Bold, color.FgCyan).FprintfFunc()
var FailureTextDisplay = color.New(color.Faint, color.FgHiRed).FprintfFunc()
var InfoDisplay = color.New(color.Bold, color.FgHiYellow).FprintfFunc()
var InfoTextDisplay = color.New(color.Bold, color.FgHiYellow).FprintfFunc()
var SimpleDisplay = color.New().FprintfFunc()
var SuccessDisplay = color.New(color.Bold, color.FgHiGreen).FprintfFunc()
var DescriptionDisplay = color.New(color.Faint, color.FgWhite).FprintfFunc()

var Spinner *spinner.Spinner

func ScanStartDisplay() {
	if IsSilent() {
		return
	}
	InfoDisplay(os.Stderr, "ARMO security scanner starting\n")
}

func SuccessTextDisplay(str string) {
	if IsSilent() {
		return
	}
	SuccessDisplay(os.Stderr, "[success] ")
	SimpleDisplay(os.Stderr, fmt.Sprintf("%s\n", str))

}

func ErrorDisplay(str string) {
	if IsSilent() {
		return
	}
	SuccessDisplay(os.Stderr, "[Error] ")
	SimpleDisplay(os.Stderr, fmt.Sprintf("%s\n", str))

}

func ProgressTextDisplay(str string) {
	if IsSilent() {
		return
	}
	InfoDisplay(os.Stderr, "[progress] ")
	SimpleDisplay(os.Stderr, fmt.Sprintf("%s\n", str))

}
func StartSpinner() {
	if !IsSilent() && isatty.IsTerminal(os.Stdout.Fd()) {
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
