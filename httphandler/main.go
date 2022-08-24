package main

import (
	logger "github.com/kubescape/go-logger"
	_ "github.com/kubescape/kubescape/v2/httphandler/docs"
	"github.com/kubescape/kubescape/v2/httphandler/listener"
)

func main() {
	logger.L().Fatal(listener.SetupHTTPListener().Error())
}
