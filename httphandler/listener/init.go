package listener

import (
	"os"

	"github.com/armosec/kubescape/v2/core/cautils/getter"
	logger "github.com/dwertent/go-logger"
	"github.com/dwertent/go-logger/zaplogger"
)

func initialize() error {
	logger.InitLogger(zaplogger.LoggerName)

	initializeSaaSEnv()
	return nil
}

func initializeSaaSEnv() {

	saasEnv := os.Getenv("KS_SAAS_ENV")
	switch saasEnv {
	case "dev", "development":
		logger.L().Debug("setting dev env")
		getter.SetARMOAPIConnector(getter.NewARMOAPIDev())
	case "stage", "staging":
		logger.L().Debug("setting staging env")
		getter.SetARMOAPIConnector(getter.NewARMOAPIStaging())
	default:
		logger.L().Debug("setting prod env")
		getter.SetARMOAPIConnector(getter.NewARMOAPIProd())
	}
}
