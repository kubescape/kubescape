package zaplogger

import (
	"os"

	"github.com/armosec/kubescape/cautils/logger/helpers"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type ZapLogger struct {
	zapL *zap.Logger
	cfg  zap.Config
}

func NewZapLogger() *ZapLogger {
	ec := zap.NewProductionEncoderConfig()
	ec.EncodeTime = zapcore.RFC3339TimeEncoder
	cfg := zap.NewProductionConfig()
	cfg.DisableCaller = true
	cfg.DisableStacktrace = true
	cfg.Encoding = "json"
	cfg.EncoderConfig = ec

	zapLogger, err := cfg.Build()
	if err != nil {
		panic(err)
	}
	return &ZapLogger{
		zapL: zapLogger,
		cfg:  cfg,
	}
}

func (zl *ZapLogger) GetLevel() string     { return zl.cfg.Level.Level().String() }
func (zl *ZapLogger) SetWriter(w *os.File) {}
func (zl *ZapLogger) GetWriter() *os.File  { return nil }
func GetWriter() *os.File                  { return nil }

func (zl *ZapLogger) SetLevel(level string) error {
	l := zapcore.Level(1)
	err := l.Set(level)
	if err == nil {
		zl.cfg.Level.SetLevel(l)
	}
	return err
}
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
