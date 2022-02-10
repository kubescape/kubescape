package main

import (
	"os"

	"github.com/armosec/kubescape/clihandler/cmd"
	"github.com/armosec/kubescape/httphandler"
)

func main() {
	if os.Getenv("KS_RUN_PROMETHEUS_SERVER") == "true" {
		httphandler.PrometheusListener() // beta version
	} else {
		cmd.Execute()
	}
}
