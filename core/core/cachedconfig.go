package core

import (
	"fmt"

	metav1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"
)

func (ks *Kubescape) SetCachedConfig(setConfig *metav1.SetConfig) error {

	tenant := getTenantConfig(nil, "", "", getKubernetesApi())

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

// View cached configurations
func (ks *Kubescape) ViewCachedConfig(viewConfig *metav1.ViewConfig) error {
	tenant := getTenantConfig(nil, "", "", getKubernetesApi()) // change k8sinterface
	fmt.Fprintf(viewConfig.Writer, "%s\n", tenant.GetConfigObj().Config())
	return nil
}

func (ks *Kubescape) DeleteCachedConfig(deleteConfig *metav1.DeleteConfig) error {

	tenant := getTenantConfig(nil, "", "", getKubernetesApi()) // change k8sinterface
	return tenant.DeleteCachedConfig()
}
