package prettylogger

import (
	"io"

	"github.com/armosec/kubescape/cautils/logger/helpers"
	"github.com/fatih/color"
)

var prefixError = color.New(color.Bold, color.FgHiRed).FprintfFunc()
var prefixWarning = color.New(color.Bold, color.FgHiYellow).FprintfFunc()
var prefixInfo = color.New(color.Bold, color.FgCyan).FprintfFunc()
var prefixSuccess = color.New(color.Bold, color.FgHiGreen).FprintfFunc()
var prefixDebug = color.New(color.Bold, color.FgWhite).FprintfFunc()
var message = color.New().FprintfFunc()

func prefix(l helpers.Level) func(w io.Writer, format string, a ...interface{}) {
	switch l {
	case helpers.DebugLevel:
		return prefixDebug
	case helpers.InfoLevel:
		return prefixInfo
	case helpers.SuccessLevel:
		return prefixSuccess
	case helpers.WarningLevel:
		return prefixWarning
	case helpers.ErrorLevel, helpers.FatalLevel:
		return prefixError
	}
	return message
}

func DisableColor(flag bool) {
	if flag {
		color.NoColor = true
	}
}
