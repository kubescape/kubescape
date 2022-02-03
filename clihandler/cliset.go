package clihandler

import (
	"github.com/armosec/kubescape/clihandler/cliobjects"
)

func CliSetConfig(setConfig *cliobjects.SetConfig) error {

	tenant := getTenantConfig("", "", getKubernetesApi())

	if setConfig.Account != "" {
		tenant.GetConfigObj().AccountID = setConfig.Account
	}
	if setConfig.AccessKey != "" {
		tenant.GetConfigObj().AccessKey = setConfig.AccessKey
	}
	if setConfig.ClientID != "" {
		tenant.GetConfigObj().ClientID = setConfig.ClientID
	}

	return tenant.UpdateCachedConfig()
}
