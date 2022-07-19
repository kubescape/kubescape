package main

import (
	"github.com/armosec/kubescape/v2/cmd"
	logger "github.com/dwertent/go-logger"
)

func main() {
	if err := cmd.Execute(); err != nil {
		logger.L().Fatal(err.Error())
	}
}
