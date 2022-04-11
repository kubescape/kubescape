package main

import (
	"github.com/armosec/kubescape/v2/cmd"
	"github.com/armosec/kubescape/v2/core/cautils/logger"
)

func main() {
	if err := cmd.Execute(); err != nil {
		logger.L().Fatal(err.Error())
	}
}
