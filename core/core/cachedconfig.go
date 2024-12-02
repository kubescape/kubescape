package core

import (
	"context"
	"fmt"

	"github.com/kubescape/kubescape/v3/core/cautils"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
)

func (ks *Kubescape) SetCachedConfig(setConfig *metav1.SetConfig) error {
	tenant := cautils.GetTenantConfig("", "", "", "", nil)

	if setConfig.Account != "" {
		tenant.GetConfigObj().AccountID = setConfig.Account
	}
	if setConfig.AccessKey != "" {
		tenant.GetConfigObj().AccessKey = setConfig.AccessKey
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
	tenant := cautils.GetTenantConfig("", "", "", "", getKubernetesApi()) // change k8sinterface
	fmt.Fprintf(viewConfig.Writer, "%s\n", tenant.GetConfigObj().Config())
	return nil
}

func (ks *Kubescape) DeleteCachedConfig(ctx context.Context, deleteConfig *metav1.DeleteConfig) error {

	tenant := cautils.GetTenantConfig("", "", "", "", nil) // change k8sinterface
	return tenant.DeleteCachedConfig(ctx)
}
