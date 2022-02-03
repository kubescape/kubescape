package prettylogger

import (
	"fmt"
	"os"

	"github.com/armosec/kubescape/cautils/logger/helpers"
)

type PrettyLogger struct {
	writer *os.File
	level  Level
}

func NewPrettyLogger() *PrettyLogger {
	return &PrettyLogger{
		writer: os.Stderr, // default to stderr
		level:  InfoLevel,
	}
}

func (pl *PrettyLogger) SetLevel(level string) { pl.level = toLevel(level) }
func (pl *PrettyLogger) GetLevel() string      { return pl.level.string() }
func (pl *PrettyLogger) SetWriter(w *os.File)  { pl.writer = w }
func (pl *PrettyLogger) GetWriter() *os.File   { return pl.writer }

func (pl *PrettyLogger) Fatal(msg string, details ...helpers.IDetails) {
	pl.print(FatalLevel, msg, details...)
	os.Exit(1)
}
func (pl *PrettyLogger) Error(msg string, details ...helpers.IDetails) {
	pl.print(ErrorLevel, msg, details...)
}
func (pl *PrettyLogger) Warning(msg string, details ...helpers.IDetails) {
	pl.print(WarningLevel, msg, details...)
}
func (pl *PrettyLogger) Info(msg string, details ...helpers.IDetails) {
	pl.print(InfoLevel, msg, details...)
}
func (pl *PrettyLogger) Debug(msg string, details ...helpers.IDetails) {
	pl.print(DebugLevel, msg, details...)
}
func (pl *PrettyLogger) Success(msg string, details ...helpers.IDetails) {
	pl.print(SuccessLevel, msg, details...)
}

func (pl *PrettyLogger) print(level Level, msg string, details ...helpers.IDetails) {
	if !level.skip(pl.level) {
		level.prefix()(pl.writer, "[%s] ", level.string())
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
