package core

import (
	"fmt"
	"io"

	"github.com/armosec/kubescape/core/metadata/cliobjects"
)

func SetCachedConfig(setConfig *cliobjects.SetConfig) error {

	tenant := getTenantConfig("", "", getKubernetesApi())

	if setConfig.Account != "" {
		tenant.GetConfigObj().AccountID = setConfig.Account
	}
	if setConfig.SecretKey != "" {
		tenant.GetConfigObj().SecretKey = setConfig.SecretKey
	}
	if setConfig.ClientID != "" {
		tenant.GetConfigObj().ClientID = setConfig.ClientID
	}

	return tenant.UpdateCachedConfig()
}

// os.Stderr

// View cached configurations
func ViewCachedConfig(writer io.Writer) error {
	tenant := getTenantConfig("", "", getKubernetesApi()) // change k8sinterface
	fmt.Fprintf(writer, "%s\n", tenant.GetConfigObj().Config())
	return nil
}

func DeleteCachedConfig() error {

	tenant := getTenantConfig("", "", getKubernetesApi()) // change k8sinterface
	return tenant.DeleteCachedConfig()
}
