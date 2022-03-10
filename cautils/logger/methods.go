package logger

import (
	"os"
	"strings"

	"github.com/armosec/kubescape/cautils/logger/helpers"
	"github.com/armosec/kubescape/cautils/logger/nonelogger"
	"github.com/armosec/kubescape/cautils/logger/prettylogger"
	"github.com/armosec/kubescape/cautils/logger/zaplogger"
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

	LoggerName() string
}

var l ILogger

// Return initialized logger. If logger not initialized, will call InitializeLogger() with the default value
func L() ILogger {
	if l == nil {
		InitDefaultLogger()
	}
	return l
}

/* InitLogger initialize desired logger

Use:
InitLogger("<logger name>")

Supported logger names (call ListLoggersNames() for listing supported loggers)
- "zap": Logger from package "go.uber.org/zap"
- "pretty", "colorful": Human friendly colorful logger
- "none", "mock", "empty", "ignore": Logger will not print anything

Default:
- "pretty"

e.g.
InitLogger("none") -> will initialize the mock logger

*/
func InitLogger(loggerName string) {

	switch strings.ToLower(loggerName) {
	case zaplogger.LoggerName:
		l = zaplogger.NewZapLogger()
	case prettylogger.LoggerName, "colorful":
		l = prettylogger.NewPrettyLogger()
	case nonelogger.LoggerName, "mock", "empty", "ignore":
		l = nonelogger.NewNoneLogger()
	default:
		InitDefaultLogger()
	}
}

func InitDefaultLogger() {
	l = prettylogger.NewPrettyLogger()
}

func DisableColor(flag bool) {
	prettylogger.DisableColor(flag)
}

func ListLoggersNames() []string {
	return []string{prettylogger.LoggerName, zaplogger.LoggerName, nonelogger.LoggerName}
}
