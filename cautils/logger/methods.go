package logger

import (
	"os"

	"github.com/armosec/kubescape/cautils/logger/helpers"
	"github.com/armosec/kubescape/cautils/logger/prettylogger"
	"github.com/armosec/kubescape/cautils/logger/zaplogger"
	"github.com/mattn/go-isatty"
)

type ILogger interface {
	Fatal(msg string, details ...helpers.IDetails) // print log and exit 1
	Error(msg string, details ...helpers.IDetails)
	Success(msg string, details ...helpers.IDetails)
	Warning(msg string, details ...helpers.IDetails)
	Info(msg string, details ...helpers.IDetails)
	Debug(msg string, details ...helpers.IDetails)

	SetLevel(level string) error
	GetLevel() string

	SetWriter(w *os.File)
	GetWriter() *os.File
}

var l ILogger

func L() ILogger {
	if l == nil {
		InitializeLogger()
	}
	return l
}

func InitializeLogger() {

	if isatty.IsTerminal(os.Stdout.Fd()) {
		l = prettylogger.NewPrettyLogger()
	} else {
		l = zaplogger.NewZapLogger()
	}
}
