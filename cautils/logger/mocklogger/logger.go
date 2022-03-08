package mocklogger

import (
	"os"

	"github.com/armosec/kubescape/cautils/logger/helpers"
)

type MockLogger struct {
}

func NewMockLogger() *MockLogger {
	return &MockLogger{}
}

func (zl *MockLogger) GetLevel() string                                { return "" }
func (zl *MockLogger) SetWriter(w *os.File)                            {}
func (zl *MockLogger) GetWriter() *os.File                             { return nil }
func (zl *MockLogger) SetLevel(level string) error                     { return nil }
func (zl *MockLogger) Fatal(msg string, details ...helpers.IDetails)   {}
func (zl *MockLogger) Error(msg string, details ...helpers.IDetails)   {}
func (zl *MockLogger) Warning(msg string, details ...helpers.IDetails) {}
func (zl *MockLogger) Success(msg string, details ...helpers.IDetails) {}
func (zl *MockLogger) Info(msg string, details ...helpers.IDetails)    {}
func (zl *MockLogger) Debug(msg string, details ...helpers.IDetails)   {}
