package prettylogger

import (
	"fmt"
	"os"

	"github.com/armosec/kubescape/cautils/logger/helpers"
)

type PrettyLogger struct {
	writer *os.File
	level  helpers.Level
}

func NewPrettyLogger() *PrettyLogger {
	return &PrettyLogger{
		writer: os.Stderr, // default to stderr
		level:  helpers.InfoLevel,
	}
}

func (pl *PrettyLogger) GetLevel() string     { return pl.level.String() }
func (pl *PrettyLogger) SetWriter(w *os.File) { pl.writer = w }
func (pl *PrettyLogger) GetWriter() *os.File  { return pl.writer }

func (pl *PrettyLogger) SetLevel(level string) error {
	pl.level = helpers.ToLevel(level)
	if pl.level == helpers.UnknownLevel {
		return fmt.Errorf("level '%s' unknown", level)
	}
	return nil
}
func (pl *PrettyLogger) Fatal(msg string, details ...helpers.IDetails) {
	pl.print(helpers.FatalLevel, msg, details...)
	os.Exit(1)
}
func (pl *PrettyLogger) Error(msg string, details ...helpers.IDetails) {
	pl.print(helpers.ErrorLevel, msg, details...)
}
func (pl *PrettyLogger) Warning(msg string, details ...helpers.IDetails) {
	pl.print(helpers.WarningLevel, msg, details...)
}
func (pl *PrettyLogger) Info(msg string, details ...helpers.IDetails) {
	pl.print(helpers.InfoLevel, msg, details...)
}
func (pl *PrettyLogger) Debug(msg string, details ...helpers.IDetails) {
	pl.print(helpers.DebugLevel, msg, details...)
}
func (pl *PrettyLogger) Success(msg string, details ...helpers.IDetails) {
	pl.print(helpers.SuccessLevel, msg, details...)
}

func (pl *PrettyLogger) print(level helpers.Level, msg string, details ...helpers.IDetails) {
	if !level.Skip(pl.level) {
		prefix(level)(pl.writer, "[%s] ", level.String())
		message(pl.writer, fmt.Sprintf("%s %s\n", msg, detailsToString(details)))
	}

}

func detailsToString(details []helpers.IDetails) string {
	s := ""
	for i := range details {
		s += fmt.Sprintf("%s: %s", details[i].Key(), details[i].Value())
		if i < len(details)-1 {
			s += ";"
		}
	}
	return s
}
