package main

import (
	"github.com/armosec/kubescape/v2/cmd"
	"github.com/armosec/kubescape/v2/core/cautils/logger"
)

func main() {
	ks := cmd.NewDefaultKubescapeCommand()
	err := ks.Execute()
	if err != nil {
		logger.L().Fatal(err.Error())
	}
}
