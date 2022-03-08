package logger

import (
	"os"
	"strings"

	"github.com/armosec/kubescape/cautils/logger/helpers"
	"github.com/armosec/kubescape/cautils/logger/mocklogger"
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

// Return initialized logger. If logger not initialized, will call InitializeLogger() with the default value
func L() ILogger {
	if l == nil {
		InitializeLogger("")
	}
	return l
}

/* InitializeLogger initialize desired logger

Use:
InitializeLogger("<logger name>")

Supported logger names
- "zap": Logger from package "go.uber.org/zap"
- "pretty", "colorful": Human friendly colorful logger
- "mock", "empty", "ignore": Logger will be totally ignored

e.g.
InitializeLogger("mock") -> will initialize the mock logger

Default:
If isatty.IsTerminal(os.Stdout.Fd()):
	"pretty"
else
	"zap"

*/
func InitializeLogger(loggerName string) {

	switch strings.ToLower(loggerName) {
	case "zap":
		l = zaplogger.NewZapLogger()
	case "pretty", "colorful":
		l = prettylogger.NewPrettyLogger()
	case "mock", "empty", "ignore":
		l = mocklogger.NewMockLogger()
	default:
		if isatty.IsTerminal(os.Stdout.Fd()) {
			l = prettylogger.NewPrettyLogger()
		} else {
			l = zaplogger.NewZapLogger()
		}
	}
}
