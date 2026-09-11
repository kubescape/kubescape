package cautils

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type ConfigValidationStatus string
type ConfigValidationProfile string

const (
	ConfigValidationStatusOK      ConfigValidationStatus = "ok"
	ConfigValidationStatusMissing ConfigValidationStatus = "missing"
	ConfigValidationStatusInvalid ConfigValidationStatus = "invalid"

	ConfigValidationProfileCloud   ConfigValidationProfile = "cloud"
	ConfigValidationProfileOffline ConfigValidationProfile = "offline"
)

type ConfigValidationCheck struct {
	Field   string                 `json:"field" yaml:"field"`
	Status  ConfigValidationStatus `json:"status" yaml:"status"`
	Message string                 `json:"message" yaml:"message"`
}

type ConfigValidationResult struct {
	Valid   bool                    `json:"valid" yaml:"valid"`
	Profile ConfigValidationProfile `json:"profile" yaml:"profile"`
	Checks  []ConfigValidationCheck `json:"checks" yaml:"checks"`
}

var requiredConfigFields = []string{
	"accountID",
	"accessKey",
	"cloudAPIURL",
	"cloudReportURL",
}

func ValidateConfig(cfg *ConfigObj, profile ConfigValidationProfile) ConfigValidationResult {
	if cfg == nil {
		cfg = &ConfigObj{}
	}
	profile = normalizeConfigValidationProfile(profile)
	checks := validateConfigForProfile(cfg, profile)
	return ConfigValidationResult{
		Valid:   configValidationChecksPass(checks),
		Profile: profile,
		Checks:  checks,
	}
}

func normalizeConfigValidationProfile(profile ConfigValidationProfile) ConfigValidationProfile {
	switch ConfigValidationProfile(strings.ToLower(strings.TrimSpace(string(profile)))) {
	case "", ConfigValidationProfileCloud:
		return ConfigValidationProfileCloud
	case ConfigValidationProfileOffline:
		return ConfigValidationProfileOffline
	default:
		return profile
	}
}

func ValidateConfigProfile(profile ConfigValidationProfile) error {
	normalized := normalizeConfigValidationProfile(profile)
	switch normalized {
	case ConfigValidationProfileCloud, ConfigValidationProfileOffline:
		return nil
	default:
		return fmt.Errorf("unsupported validation profile %q", profile)
	}
}

func validateConfigForProfile(cfg *ConfigObj, profile ConfigValidationProfile) []ConfigValidationCheck {
	switch profile {
	case ConfigValidationProfileOffline:
		return []ConfigValidationCheck{
			validateOptionalConfigField("accountID", cfg.AccountID, "account ID is configured", "accountID is not required for offline validation"),
			validateOptionalConfigField("accessKey", cfg.AccessKey, "access key is configured", "accessKey is not required for offline validation"),
			validateOptionalURLConfigField("cloudAPIURL", cfg.CloudAPIURL, "cloud API URL is configured", "cloudAPIURL is not configured; offline scans can use local policy sources"),
			validateOptionalURLConfigField("cloudReportURL", cfg.CloudReportURL, "cloud report URL is configured", "cloudReportURL is not configured; offline scans can skip cloud submission"),
		}
	default:
		return []ConfigValidationCheck{
			validateRequiredConfigField("accountID", cfg.AccountID, "account ID is configured"),
			validateRequiredConfigField("accessKey", cfg.AccessKey, "access key is configured"),
			validateRequiredURLConfigField("cloudAPIURL", cfg.CloudAPIURL, "cloud API URL is configured"),
			validateRequiredURLConfigField("cloudReportURL", cfg.CloudReportURL, "cloud report URL is configured"),
		}
	}
}

func FormatConfigValidationResult(result ConfigValidationResult, format string, includeOK bool) ([]byte, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "text"
	}
	result.Checks = filterConfigValidationChecks(result.Checks, includeOK)
	switch format {
	case "json":
		return json.MarshalIndent(result, "", "  ")
	case "yaml":
		return yaml.Marshal(result)
	case "text":
		return formatConfigValidationText(result), nil
	default:
		return nil, fmt.Errorf("unsupported output format %q", format)
	}
}

func configValidationChecksPass(checks []ConfigValidationCheck) bool {
	for _, check := range checks {
		if check.Status != ConfigValidationStatusOK {
			return false
		}
	}
	return true
}

func validateRequiredConfigField(field, value, okMessage string) ConfigValidationCheck {
	value = strings.TrimSpace(value)
	if value == "" {
		return ConfigValidationCheck{
			Field:   field,
			Status:  ConfigValidationStatusMissing,
			Message: fmt.Sprintf("%s is required", field),
		}
	}
	return ConfigValidationCheck{
		Field:   field,
		Status:  ConfigValidationStatusOK,
		Message: okMessage,
	}
}

func validateOptionalConfigField(field, value, okMessage, emptyMessage string) ConfigValidationCheck {
	value = strings.TrimSpace(value)
	if value == "" {
		return ConfigValidationCheck{
			Field:   field,
			Status:  ConfigValidationStatusOK,
			Message: emptyMessage,
		}
	}
	return ConfigValidationCheck{
		Field:   field,
		Status:  ConfigValidationStatusOK,
		Message: okMessage,
	}
}

func validateRequiredURLConfigField(field, value, okMessage string) ConfigValidationCheck {
	value = strings.TrimSpace(value)
	if value == "" {
		return ConfigValidationCheck{
			Field:   field,
			Status:  ConfigValidationStatusMissing,
			Message: fmt.Sprintf("%s is required", field),
		}
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil {
		return ConfigValidationCheck{
			Field:   field,
			Status:  ConfigValidationStatusInvalid,
			Message: fmt.Sprintf("%s must be a valid URL: %v", field, err),
		}
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ConfigValidationCheck{
			Field:   field,
			Status:  ConfigValidationStatusInvalid,
			Message: fmt.Sprintf("%s URL scheme must be http or https", field),
		}
	}
	if parsed.Host == "" {
		return ConfigValidationCheck{
			Field:   field,
			Status:  ConfigValidationStatusInvalid,
			Message: fmt.Sprintf("%s URL host must not be empty", field),
		}
	}
	return ConfigValidationCheck{
		Field:   field,
		Status:  ConfigValidationStatusOK,
		Message: okMessage,
	}
}

func validateOptionalURLConfigField(field, value, okMessage, emptyMessage string) ConfigValidationCheck {
	value = strings.TrimSpace(value)
	if value == "" {
		return ConfigValidationCheck{
			Field:   field,
			Status:  ConfigValidationStatusOK,
			Message: emptyMessage,
		}
	}
	return validateRequiredURLConfigField(field, value, okMessage)
}

func filterConfigValidationChecks(checks []ConfigValidationCheck, includeOK bool) []ConfigValidationCheck {
	filtered := make([]ConfigValidationCheck, 0, len(checks))
	for _, check := range checks {
		if includeOK || check.Status != ConfigValidationStatusOK {
			filtered = append(filtered, check)
		}
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		return configValidationFieldOrder(filtered[i].Field) < configValidationFieldOrder(filtered[j].Field)
	})
	return filtered
}

func configValidationFieldOrder(field string) int {
	for i, required := range requiredConfigFields {
		if field == required {
			return i
		}
	}
	return len(requiredConfigFields)
}

func formatConfigValidationText(result ConfigValidationResult) []byte {
	lines := []string{
		fmt.Sprintf("valid: %t", result.Valid),
		fmt.Sprintf("profile: %s", result.Profile),
	}
	for _, check := range result.Checks {
		lines = append(lines, fmt.Sprintf("%s: %s - %s", check.Field, check.Status, check.Message))
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}
