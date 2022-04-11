package main

import (
	"github.com/armosec/kubescape/v2/core/cautils/logger"
	"github.com/armosec/kubescape/v2/httphandler/listener"
)

func main() {
	logger.L().Fatal(listener.SetupHTTPListener().Error())
}
