package clihandler

import "fmt"

func CliView() error {
	tenant := getTenantConfig("", "", getKubernetesApi()) // change k8sinterface
	fmt.Printf("%s\n", tenant.GetConfigObj().Config())
	return nil
}
