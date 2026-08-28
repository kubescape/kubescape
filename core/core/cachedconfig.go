package core

import (
	"fmt"
	"strings"

	"github.com/kubescape/kubescape/v4/core/cautils"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
)

func (ks *Kubescape) SetCachedConfig(setConfig *metav1.SetConfig) error {
	tenant := cautils.GetTenantConfig(ks.Context(), "", "", "", "", nil)

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

func getNormalizedKey(key string) string {
	key = strings.ToLower(key)
	key = strings.ReplaceAll(key, "-", "")
	key = strings.ReplaceAll(key, "_", "")
	if key == "account" {
		return "accountid"
	}
	return key
}

// View cached configurations
func (ks *Kubescape) ViewCachedConfig(viewConfig *metav1.ViewConfig) error {
	tenant := cautils.GetTenantConfig(ks.Context(), "", "", "", "", getKubernetesApi()) // change k8sinterface
	configObj := tenant.GetConfigObj()

	if viewConfig.Key != "" {
		normalizedKey := getNormalizedKey(viewConfig.Key)
		var val string
		var found bool

		switch normalizedKey {
		case "accountid":
			val = configObj.AccountID
			found = true
		case "clustername":
			val = configObj.ClusterName
			found = true
		case "cloudreporturl":
			val = configObj.CloudReportURL
			found = true
		case "cloudapiurl":
			val = configObj.CloudAPIURL
			found = true
		case "accesskey":
			val = configObj.AccessKey
			found = true
		}

		if !found {
			return fmt.Errorf("key %q is not supported", viewConfig.Key)
		}
		if val == "" {
			return fmt.Errorf("key %q is not set", viewConfig.Key)
		}

		if viewConfig.Writer != nil {
			_, err := fmt.Fprint(viewConfig.Writer, val+"\n")
			return err
		}
		return nil
	}

	outputFormat := viewConfig.OutputFormat
	if outputFormat == "" {
		outputFormat = "text"
	}

	formatted, err := cautils.FormatConfigOutput(configObj, outputFormat, viewConfig.IncludeEmpty)
	if err != nil {
		return err
	}

	if viewConfig.Writer != nil {
		_, err = fmt.Fprint(viewConfig.Writer, string(formatted))
		return err
	}

	return nil
}

func (ks *Kubescape) DeleteCachedConfig(deleteConfig *metav1.DeleteConfig) error {

	tenant := cautils.GetTenantConfig(ks.Context(), "", "", "", "", nil) // change k8sinterface
	return tenant.DeleteCachedConfig(ks.Context())
}
