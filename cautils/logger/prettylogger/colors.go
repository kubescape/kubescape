package prettylogger

import (
	"github.com/fatih/color"
)

var prefixError = color.New(color.Bold, color.FgHiRed).FprintfFunc()
var prefixWarning = color.New(color.Bold, color.FgHiYellow).FprintfFunc()
var prefixInfo = color.New(color.Bold, color.FgCyan).FprintfFunc()
var prefixSuccess = color.New(color.Bold, color.FgHiGreen).FprintfFunc()
var prefixDebug = color.New(color.Bold, color.FgWhite).FprintfFunc()
var message = color.New().FprintfFunc()
