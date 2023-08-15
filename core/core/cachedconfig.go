package core

import (
	"context"
	"fmt"

	metav1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"
)

func (ks *Kubescape) SetCachedConfig(setConfig *metav1.SetConfig) error {

	tenant := getTenantConfig("", "", "", getKubernetesApi())

	if setConfig.Account != "" {
		tenant.GetConfigObj().AccountID = setConfig.Account
	}
	if setConfig.CloudAPIURL != "" {
		tenant.GetConfigObj().CloudAPIURL = setConfig.CloudAPIURL
	}
	if setConfig.CloudReportURL != "" {
		tenant.GetConfigObj().CloudReportURL = setConfig.CloudReportURL
	}

	return tenant.UpdateCachedConfig()
}

// View cached configurations
func (ks *Kubescape) ViewCachedConfig(viewConfig *metav1.ViewConfig) error {
	tenant := getTenantConfig("", "", "", getKubernetesApi()) // change k8sinterface
	fmt.Fprintf(viewConfig.Writer, "%s\n", tenant.GetConfigObj().Config())
	return nil
}

func (ks *Kubescape) DeleteCachedConfig(ctx context.Context, deleteConfig *metav1.DeleteConfig) error {

	tenant := getTenantConfig("", "", "", getKubernetesApi()) // change k8sinterface
	return tenant.DeleteCachedConfig(ctx)
}
