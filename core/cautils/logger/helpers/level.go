package helpers

import (
	"strings"
)

type Level int8

const (
	UnknownLevel Level = iota - -1
	DebugLevel
	InfoLevel //default
	SuccessLevel
	WarningLevel
	ErrorLevel
	FatalLevel

	_defaultLevel = InfoLevel
	_minLevel     = DebugLevel
	_maxLevel     = FatalLevel
)

func ToLevel(level string) Level {
	switch strings.ToLower(level) {
	case "debug":
		return DebugLevel
	case "info":
		return InfoLevel
	case "success":
		return SuccessLevel
	case "warning", "warn":
		return WarningLevel
	case "error":
		return ErrorLevel
	case "fatal":
		return FatalLevel
	default:
		return UnknownLevel
	}
}
func (l Level) String() string {
	switch l {
	case DebugLevel:
		return "debug"
	case InfoLevel:
		return "info"
	case SuccessLevel:
		return "success"
	case WarningLevel:
		return "warning"
	case ErrorLevel:
		return "error"
	case FatalLevel:
		return "fatal"
	}
	return ""
}

func (l Level) Skip(l2 Level) bool {
	return l < l2
}

func SupportedLevels() []string {
	levels := []string{}
	for i := _minLevel; i <= _maxLevel; i++ {
		levels = append(levels, i.String())
	}
	return levels
}
