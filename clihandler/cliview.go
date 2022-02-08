package clihandler

import (
	"fmt"
	"os"
)

func CliView() error {
	tenant := getTenantConfig("", "", getKubernetesApi()) // change k8sinterface
	fmt.Fprintf(os.Stderr, "%s\n", tenant.GetConfigObj().Config())
	return nil
}
