package cautils

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestValidateConfig_AllRequiredFieldsPresent(t *testing.T) {
	result := ValidateConfig(validConfigForValidation(), ConfigValidationProfileCloud)

	assert.True(t, result.Valid)
	assert.Equal(t, ConfigValidationProfileCloud, result.Profile)
	require.Len(t, result.Checks, 4)
	for _, check := range result.Checks {
		assert.Equal(t, ConfigValidationStatusOK, check.Status)
		assert.NotEmpty(t, check.Message)
	}
}

func TestValidateConfig_OfflineProfileAllowsEmptyCloudFields(t *testing.T) {
	result := ValidateConfig(&ConfigObj{}, ConfigValidationProfileOffline)

	assert.True(t, result.Valid)
	assert.Equal(t, ConfigValidationProfileOffline, result.Profile)
	require.Len(t, result.Checks, 4)
	for _, check := range result.Checks {
		assert.Equal(t, ConfigValidationStatusOK, check.Status)
		assert.Contains(t, check.Message, "not")
	}
}

func TestValidateConfig_OfflineProfileValidatesURLsWhenPresent(t *testing.T) {
	cfg := &ConfigObj{
		CloudAPIURL:    "https://api.example.com",
		CloudReportURL: "ftp://report.example.com",
	}

	result := ValidateConfig(cfg, ConfigValidationProfileOffline)

	assert.False(t, result.Valid)
	assertConfigCheck(t, result.Checks, "accountID", ConfigValidationStatusOK)
	assertConfigCheck(t, result.Checks, "accessKey", ConfigValidationStatusOK)
	assertConfigCheck(t, result.Checks, "cloudAPIURL", ConfigValidationStatusOK)
	assertConfigCheck(t, result.Checks, "cloudReportURL", ConfigValidationStatusInvalid)
}

func TestFormatConfigValidationResultOfflineProfileShowsOnlyFailuresByDefault(t *testing.T) {
	result := ValidateConfig(&ConfigObj{
		CloudAPIURL:    "https://api.example.com",
		CloudReportURL: "ssh://report.example.com",
	}, ConfigValidationProfileOffline)

	output, err := FormatConfigValidationResult(result, "json", false)
	require.NoError(t, err)

	var payload ConfigValidationResult
	require.NoError(t, json.Unmarshal(output, &payload))
	assert.False(t, payload.Valid)
	assert.Equal(t, ConfigValidationProfileOffline, payload.Profile)
	require.Len(t, payload.Checks, 1)
	assert.Equal(t, "cloudReportURL", payload.Checks[0].Field)
	assert.Equal(t, ConfigValidationStatusInvalid, payload.Checks[0].Status)
}

func TestValidateConfig_DefaultsToCloudProfile(t *testing.T) {
	result := ValidateConfig(validConfigForValidation(), "")

	assert.True(t, result.Valid)
	assert.Equal(t, ConfigValidationProfileCloud, result.Profile)
}

func TestValidateConfigProfile(t *testing.T) {
	tests := []struct {
		name    string
		profile ConfigValidationProfile
		wantErr string
	}{
		{name: "empty defaults to cloud", profile: ""},
		{name: "cloud", profile: ConfigValidationProfileCloud},
		{name: "cloud with spaces", profile: " CLOUD "},
		{name: "offline", profile: ConfigValidationProfileOffline},
		{name: "offline with spaces", profile: " offline "},
		{name: "unsupported", profile: "strict", wantErr: `unsupported validation profile "strict"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfigProfile(tt.profile)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tt.wantErr)
		})
	}
}

func TestValidateConfig_NilConfigReportsMissingRequiredFields(t *testing.T) {
	result := ValidateConfig(nil, ConfigValidationProfileCloud)

	assert.False(t, result.Valid)
	require.Len(t, result.Checks, 4)
	assertConfigCheck(t, result.Checks, "accountID", ConfigValidationStatusMissing)
	assertConfigCheck(t, result.Checks, "accessKey", ConfigValidationStatusMissing)
	assertConfigCheck(t, result.Checks, "cloudAPIURL", ConfigValidationStatusMissing)
	assertConfigCheck(t, result.Checks, "cloudReportURL", ConfigValidationStatusMissing)
}

func TestValidateConfig_TrimsRequiredFields(t *testing.T) {
	cfg := validConfigForValidation()
	cfg.AccountID = "   "
	cfg.AccessKey = "\t"

	result := ValidateConfig(cfg, ConfigValidationProfileCloud)

	assert.False(t, result.Valid)
	assertConfigCheck(t, result.Checks, "accountID", ConfigValidationStatusMissing)
	assertConfigCheck(t, result.Checks, "accessKey", ConfigValidationStatusMissing)
}

func TestValidateConfig_InvalidCloudAPIURL(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantText  string
		wantField string
	}{
		{name: "not a url", value: "not a url", wantText: "must be a valid URL", wantField: "cloudAPIURL"},
		{name: "missing host", value: "https://", wantText: "URL host must not be empty", wantField: "cloudAPIURL"},
		{name: "unsupported scheme", value: "ftp://api.example.com", wantText: "URL scheme must be http or https", wantField: "cloudAPIURL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfigForValidation()
			cfg.CloudAPIURL = tt.value

			result := ValidateConfig(cfg, ConfigValidationProfileCloud)

			assert.False(t, result.Valid)
			check := requireConfigCheck(t, result.Checks, tt.wantField)
			assert.Equal(t, ConfigValidationStatusInvalid, check.Status)
			assert.Contains(t, check.Message, tt.wantText)
		})
	}
}

func TestValidateConfig_InvalidCloudReportURL(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		wantText string
	}{
		{name: "not a url", value: "not a url", wantText: "must be a valid URL"},
		{name: "missing host", value: "http://", wantText: "URL host must not be empty"},
		{name: "unsupported scheme", value: "ssh://report.example.com", wantText: "URL scheme must be http or https"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfigForValidation()
			cfg.CloudReportURL = tt.value

			result := ValidateConfig(cfg, ConfigValidationProfileCloud)

			assert.False(t, result.Valid)
			check := requireConfigCheck(t, result.Checks, "cloudReportURL")
			assert.Equal(t, ConfigValidationStatusInvalid, check.Status)
			assert.Contains(t, check.Message, tt.wantText)
		})
	}
}

func TestFormatConfigValidationResultTextFailuresOnlyByDefault(t *testing.T) {
	result := ValidateConfig(&ConfigObj{
		AccountID:      "account-123",
		AccessKey:      "",
		CloudAPIURL:    "https://api.example.com",
		CloudReportURL: "ftp://report.example.com",
	}, ConfigValidationProfileCloud)

	output, err := FormatConfigValidationResult(result, "text", false)
	require.NoError(t, err)

	text := string(output)
	assert.Contains(t, text, "valid: false")
	assert.Contains(t, text, "profile: cloud")
	assert.Contains(t, text, "accessKey: missing")
	assert.Contains(t, text, "cloudReportURL: invalid")
	assert.NotContains(t, text, "accountID: ok")
	assert.NotContains(t, text, "cloudAPIURL: ok")
}

func TestFormatConfigValidationResultTextIncludesPassingChecks(t *testing.T) {
	result := ValidateConfig(validConfigForValidation(), ConfigValidationProfileCloud)

	output, err := FormatConfigValidationResult(result, "text", true)
	require.NoError(t, err)

	text := string(output)
	assert.Contains(t, text, "valid: true")
	assert.Contains(t, text, "profile: cloud")
	assert.Contains(t, text, "accountID: ok")
	assert.Contains(t, text, "accessKey: ok")
	assert.Contains(t, text, "cloudAPIURL: ok")
	assert.Contains(t, text, "cloudReportURL: ok")
}

func TestFormatConfigValidationResultJSON(t *testing.T) {
	result := ValidateConfig(&ConfigObj{
		AccountID:      "account-123",
		AccessKey:      "access-key",
		CloudAPIURL:    "https://api.example.com",
		CloudReportURL: "",
	}, ConfigValidationProfileCloud)

	output, err := FormatConfigValidationResult(result, "json", false)
	require.NoError(t, err)

	var payload ConfigValidationResult
	require.NoError(t, json.Unmarshal(output, &payload))
	assert.False(t, payload.Valid)
	assert.Equal(t, ConfigValidationProfileCloud, payload.Profile)
	require.Len(t, payload.Checks, 1)
	assert.Equal(t, "cloudReportURL", payload.Checks[0].Field)
	assert.Equal(t, ConfigValidationStatusMissing, payload.Checks[0].Status)
}

func TestFormatConfigValidationResultJSONIncludesPassingChecks(t *testing.T) {
	result := ValidateConfig(validConfigForValidation(), ConfigValidationProfileCloud)

	output, err := FormatConfigValidationResult(result, "json", true)
	require.NoError(t, err)

	var payload ConfigValidationResult
	require.NoError(t, json.Unmarshal(output, &payload))
	assert.True(t, payload.Valid)
	require.Len(t, payload.Checks, 4)
	assert.Equal(t, []string{"accountID", "accessKey", "cloudAPIURL", "cloudReportURL"}, validationCheckFields(payload.Checks))
}

func TestFormatConfigValidationResultYAML(t *testing.T) {
	result := ValidateConfig(&ConfigObj{
		AccountID:      "",
		AccessKey:      "access-key",
		CloudAPIURL:    "https://api.example.com",
		CloudReportURL: "https://report.example.com",
	}, ConfigValidationProfileCloud)

	output, err := FormatConfigValidationResult(result, "yaml", false)
	require.NoError(t, err)

	var payload ConfigValidationResult
	require.NoError(t, yaml.Unmarshal(output, &payload))
	assert.False(t, payload.Valid)
	assert.Equal(t, ConfigValidationProfileCloud, payload.Profile)
	require.Len(t, payload.Checks, 1)
	assert.Equal(t, "accountID", payload.Checks[0].Field)
	assert.Equal(t, ConfigValidationStatusMissing, payload.Checks[0].Status)
}

func TestFormatConfigValidationResultNormalizesFormat(t *testing.T) {
	result := ValidateConfig(validConfigForValidation(), ConfigValidationProfileCloud)

	output, err := FormatConfigValidationResult(result, " YAML ", true)
	require.NoError(t, err)

	var payload ConfigValidationResult
	require.NoError(t, yaml.Unmarshal(output, &payload))
	assert.True(t, payload.Valid)
}

func TestFormatConfigValidationResultDefaultsToText(t *testing.T) {
	result := ValidateConfig(validConfigForValidation(), ConfigValidationProfileCloud)

	output, err := FormatConfigValidationResult(result, "", false)
	require.NoError(t, err)

	assert.Equal(t, "valid: true\nprofile: cloud\n", string(output))
}

func TestFormatConfigValidationResultUnsupportedFormat(t *testing.T) {
	_, err := FormatConfigValidationResult(ValidateConfig(validConfigForValidation(), ConfigValidationProfileCloud), "table", false)

	require.Error(t, err)
	assert.Contains(t, err.Error(), `unsupported output format "table"`)
}

func TestFilterConfigValidationChecksOrdersRequiredFields(t *testing.T) {
	checks := []ConfigValidationCheck{
		{Field: "cloudReportURL", Status: ConfigValidationStatusInvalid},
		{Field: "accessKey", Status: ConfigValidationStatusMissing},
		{Field: "accountID", Status: ConfigValidationStatusOK},
		{Field: "cloudAPIURL", Status: ConfigValidationStatusOK},
	}

	filtered := filterConfigValidationChecks(checks, true)

	assert.Equal(t, []string{"accountID", "accessKey", "cloudAPIURL", "cloudReportURL"}, validationCheckFields(filtered))
}

func TestFilterConfigValidationChecksDropsOKChecks(t *testing.T) {
	checks := []ConfigValidationCheck{
		{Field: "accountID", Status: ConfigValidationStatusOK},
		{Field: "accessKey", Status: ConfigValidationStatusMissing},
		{Field: "cloudAPIURL", Status: ConfigValidationStatusOK},
	}

	filtered := filterConfigValidationChecks(checks, false)

	require.Len(t, filtered, 1)
	assert.Equal(t, "accessKey", filtered[0].Field)
}

func validConfigForValidation() *ConfigObj {
	return &ConfigObj{
		AccountID:      "account-123",
		AccessKey:      "access-key",
		CloudAPIURL:    "https://api.example.com",
		CloudReportURL: "https://report.example.com",
	}
}

func assertConfigCheck(t *testing.T, checks []ConfigValidationCheck, field string, status ConfigValidationStatus) {
	t.Helper()
	check := requireConfigCheck(t, checks, field)
	assert.Equal(t, status, check.Status)
}

func requireConfigCheck(t *testing.T, checks []ConfigValidationCheck, field string) ConfigValidationCheck {
	t.Helper()
	for _, check := range checks {
		if check.Field == field {
			return check
		}
	}
	require.FailNowf(t, "missing validation check", "field %q not found in %#v", field, checks)
	return ConfigValidationCheck{}
}

func validationCheckFields(checks []ConfigValidationCheck) []string {
	fields := make([]string, 0, len(checks))
	for _, check := range checks {
		fields = append(fields, check.Field)
	}
	return fields
}
