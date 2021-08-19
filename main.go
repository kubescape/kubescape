package main

import (
	"fmt"
	"kube-escape/cautils"
	k8sinterface "kube-escape/cautils/k8sinterface"
	"kube-escape/inputhandler/clihandler"

	"kube-escape/opaprocessor"
	"kube-escape/policyhandler"
	"kube-escape/printer"

	"os"
)

func main() {

	if err := CliSetup(); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

}

func CliSetup() error {
	k8s := k8sinterface.NewKubernetesApi()

	processNotification := make(chan *cautils.OPASessionObj)
	reportResults := make(chan *cautils.OPASessionObj)

	// policy handler setup
	cautils.SetupDefaultEnvs()
	policyHandler := policyhandler.NewPolicyHandler(&processNotification, k8s)

	// cli handler setup
	cli := clihandler.NewCLIHandler(policyHandler)
	if err := cli.Scan(); err != nil {
		panic(err)
	}

	// processor setup - rego run
	go func() {
		reporterObj := opaprocessor.NewOPAProcessor(&processNotification, &reportResults)
		reporterObj.ProcessRulesListenner()
	}()
	p := printer.NewPrinter(&reportResults)
	p.ActionPrint()

	return nil
}
