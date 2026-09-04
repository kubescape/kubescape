package core

import (
	"errors"
	"fmt"
	"strings"

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
		var foundField *cautils.ConfigOutputField

		for _, field := range cautils.ConfigOutputFields(configObj) {
			if strings.ToLower(field.Name) == normalizedKey {
				// Make a copy so we can take its address safely if needed, or just assign it
				f := field
				foundField = &f
				break
			}
		}

		if foundField == nil {
			return fmt.Errorf("key %q is not supported", viewConfig.Key)
		}
		if foundField.Value == "" {
			return fmt.Errorf("key %q is not set", viewConfig.Key)
		}

		if viewConfig.Writer != nil {
			formatted, err := cautils.FormatConfigFieldOutput(*foundField, viewConfig.OutputFormat)
			if err != nil {
				return err
			}
			_, err = viewConfig.Writer.Write(formatted)
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
	
	if len(deleteConfig.Keys) == 0 {
		return tenant.DeleteCachedConfig(ks.Context())
	}

	configObj := tenant.GetConfigObj()
	for _, key := range deleteConfig.Keys {
		normalizedKey := getNormalizedKey(key)
		switch normalizedKey {
		case "accountid":
			configObj.AccountID = ""
		case "clustername":
			configObj.ClusterName = ""
		case "cloudreporturl":
			configObj.CloudReportURL = ""
		case "cloudapiurl":
			configObj.CloudAPIURL = ""
		case "accesskey":
			configObj.AccessKey = ""
		default:
			return fmt.Errorf("unknown key: %s", key)
		}
	}
	
	return tenant.UpdateCachedConfig()
}
