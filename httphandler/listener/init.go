package listener

import (
	"os"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/go-logger/zaplogger"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
)

func initialize() error {
	initializeLoggerName()
	initializeLoggerLevel()
	initializeSaaSEnv()
	return nil
}

// initialize logger name
func initializeLoggerName() {
	loggerName := zaplogger.LoggerName
	if l := os.Getenv("KS_LOGGER_NAME"); l != "" {
		loggerName = l
	}
	logger.InitLogger(loggerName)
}

// initialize logger level
func initializeLoggerLevel() {
	loggerLevel := helpers.DebugLevel.String()
	if l := os.Getenv("KS_LOGGER_LEVEL"); l != "" {
		loggerLevel = l
	}
	if err := logger.L().SetLevel(loggerLevel); err != nil {
		logger.L().SetLevel(helpers.DebugLevel.String())
		logger.L().Error("failed to set logger level", helpers.String("level", loggerLevel), helpers.Error(err), helpers.String("default", helpers.DebugLevel.String()))
	}
}

// SetupHTTPListener set up listening http servers
func initializeSaaSEnv() {

	saasEnv := os.Getenv("KS_SAAS_ENV")
	switch saasEnv {
	case "dev", "development":
		logger.L().Debug("setting dev env")
		getter.SetKSCloudAPIConnector(getter.NewKSCloudAPIDev())
	case "stage", "staging":
		logger.L().Debug("setting staging env")
		getter.SetKSCloudAPIConnector(getter.NewKSCloudAPIStaging())
	default:
		logger.L().Debug("setting prod env")
		getter.SetKSCloudAPIConnector(getter.NewKSCloudAPIProd())
	}
}
