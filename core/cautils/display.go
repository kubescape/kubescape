package cautils

import (
	"os"
	"time"

	spinnerpkg "github.com/briandowns/spinner"
	"github.com/fatih/color"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/mattn/go-isatty"
	"github.com/schollz/progressbar/v3"
)

var FailureDisplay = color.New(color.Bold, color.FgHiRed).FprintfFunc()
var WarningDisplay = color.New(color.Bold, color.FgHiYellow).FprintfFunc()
var FailureTextDisplay = color.New(color.Faint, color.FgHiRed).FprintfFunc()
var InfoDisplay = color.New(color.Bold, color.FgCyan).FprintfFunc()
var InfoTextDisplay = color.New(color.Bold, color.FgHiYellow).FprintfFunc()
var SimpleDisplay = color.New().FprintfFunc()
var SuccessDisplay = color.New(color.Bold, color.FgHiGreen).FprintfFunc()
var DescriptionDisplay = color.New(color.Faint, color.FgWhite).FprintfFunc()
var BoldDisplay = color.New(color.Bold).SprintfFunc()

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
