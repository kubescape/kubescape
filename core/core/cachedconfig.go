package core

import (
	"errors"
	"fmt"

	"github.com/kubescape/kubescape/v4/core/cautils"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
)

var ErrInvalidCachedConfig = errors.New("cached configuration is invalid")

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

// View cached configurations
func (ks *Kubescape) ViewCachedConfig(viewConfig *metav1.ViewConfig) error {
	tenant := cautils.GetTenantConfig(ks.Context(), "", "", "", "", getKubernetesApi()) // change k8sinterface
	configObj := tenant.GetConfigObj()
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

func (ks *Kubescape) ValidateCachedConfig(validateConfig *metav1.ValidateConfig) error {
	if validateConfig == nil {
		validateConfig = &metav1.ValidateConfig{}
	}
	tenant := cautils.GetTenantConfig(ks.Context(), "", "", "", "", getKubernetesApi()) // change k8sinterface
	if err := cautils.ValidateConfigProfile(cautils.ConfigValidationProfile(validateConfig.Profile)); err != nil {
		return err
	}
	result := cautils.ValidateConfig(tenant.GetConfigObj(), cautils.ConfigValidationProfile(validateConfig.Profile))
	outputFormat := validateConfig.Format
	if outputFormat == "" {
		outputFormat = "text"
	}

	formatted, err := cautils.FormatConfigValidationResult(result, outputFormat, validateConfig.IncludeOK)
	if err != nil {
		return err
	}

	if validateConfig.Writer != nil {
		if _, err := fmt.Fprint(validateConfig.Writer, string(formatted)); err != nil {
			return err
		}
	}

	if !result.Valid {
		return ErrInvalidCachedConfig
	}
	return nil
}

func (ks *Kubescape) DeleteCachedConfig(deleteConfig *metav1.DeleteConfig) error {

	tenant := cautils.GetTenantConfig(ks.Context(), "", "", "", "", nil) // change k8sinterface
	return tenant.DeleteCachedConfig(ks.Context())
}
