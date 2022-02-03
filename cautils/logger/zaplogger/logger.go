package zaplogger

import (
	"os"

	"github.com/armosec/kubescape/cautils/logger/helpers"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type ZapLogger struct {
	zapL *zap.Logger
}

func NewZapLogger() *ZapLogger {
	return &ZapLogger{
		zapL: zap.L(),
	}
}

func (zl *ZapLogger) SetLevel(level string) {}
func (zl *ZapLogger) GetLevel() string      { return "" }
func (zl *ZapLogger) SetWriter(w *os.File)  {}
func (zl *ZapLogger) GetWriter() *os.File   { return nil }

func (zl *ZapLogger) Fatal(msg string, details ...helpers.IDetails) {
	zl.zapL.Fatal(msg, detailsToZapFields(details)...)
}

func (zl *ZapLogger) Error(msg string, details ...helpers.IDetails) {
	zl.zapL.Error(msg, detailsToZapFields(details)...)
}

func (zl *ZapLogger) Warning(msg string, details ...helpers.IDetails) {
	zl.zapL.Warn(msg, detailsToZapFields(details)...)
}

func (zl *ZapLogger) Success(msg string, details ...helpers.IDetails) {
	zl.zapL.Info(msg, detailsToZapFields(details)...)
}

func (zl *ZapLogger) Info(msg string, details ...helpers.IDetails) {
	zl.zapL.Info(msg, detailsToZapFields(details)...)
}

func (zl *ZapLogger) Debug(msg string, details ...helpers.IDetails) {
	zl.zapL.Debug(msg, detailsToZapFields(details)...)
}

func detailsToZapFields(details []helpers.IDetails) []zapcore.Field {
	zapFields := []zapcore.Field{}
	for i := range details {
		zapFields = append(zapFields, zap.Any(details[i].Key(), details[i].Value()))
	}
	return zapFields
}
