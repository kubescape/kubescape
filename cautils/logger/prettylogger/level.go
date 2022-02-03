package prettylogger

import (
	"io"
	"strings"
)

type Level int8

const (
	DebugLevel   Level = iota - 0
	InfoLevel          //default
	SuccessLevel       //default
	WarningLevel
	ErrorLevel
	FatalLevel

	_defaultLevel = InfoLevel
	// _minLevel     = DebugLevel
	// _maxLevel     = FatalLevel
)

func toLevel(level string) Level {
	switch strings.ToLower(level) {
	case "debug":
		return DebugLevel
	case "info":
		return InfoLevel
	case "success":
		return SuccessLevel
	case "warnign", "warn":
		return WarningLevel
	case "error":
		return ErrorLevel
	case "fatal":
		return FatalLevel
	default:
		return _defaultLevel
	}
}
func (l Level) string() string {
	switch l {
	case DebugLevel:
		return "debug"
	case InfoLevel:
		return "info"
	case SuccessLevel:
		return "success"
	case WarningLevel:
		return "warnign"
	case ErrorLevel, FatalLevel:
		return "error"
	}
	return ""
}

func (l Level) prefix() func(w io.Writer, format string, a ...interface{}) {
	switch l {
	case DebugLevel:
		return prefixDebug
	case InfoLevel:
		return prefixInfo
	case SuccessLevel:
		return prefixSuccess
	case WarningLevel:
		return prefixWarning
	case ErrorLevel, FatalLevel:
		return prefixError
	}
	return message
}

func (l Level) skip(l2 Level) bool {
	return l > l2
}
