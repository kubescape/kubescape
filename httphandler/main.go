package main

import (
	"github.com/armosec/kubescape/core/cautils/logger"
	"github.com/armosec/kubescape/httphandler/listener"
)

func main() {
	logger.L().Fatal(listener.SetupHTTPListener().Error())
}
