package main

import (
	_ "github.com/armosec/kubescape/v2/httphandler/docs"
	"github.com/armosec/kubescape/v2/httphandler/listener"
	logger "github.com/dwertent/go-logger"
)

func main() {
	logger.L().Fatal(listener.SetupHTTPListener().Error())
}
