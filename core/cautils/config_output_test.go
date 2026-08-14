package cautils

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestFormatConfigOutputJSON(t *testing.T) {
	cfg := &ConfigObj{
		AccountID:      "account-123",
		CloudReportURL: "https://report.example.com",
	}

	output, err := FormatConfigOutput(cfg, "json", false)
	require.NoError(t, err)

	assert.Contains(t, string(output), `"accountID": "account-123"`)
	assert.Contains(t, string(output), `"cloudReportURL": "https://report.example.com"`)
	assert.NotContains(t, string(output), `"clusterName"`)
}

func TestFormatConfigOutputYAML(t *testing.T) {
	cfg := &ConfigObj{
		AccountID:   "account-123",
		AccessKey:   "super-secret",
		ClusterName: "prod-cluster",
	}

	output, err := FormatConfigOutput(cfg, "yaml", true)
	require.NoError(t, err)

	assert.Contains(t, string(output), "accountID: account-123")
	assert.Contains(t, string(output), "accessKey: super-secret")
	assert.Contains(t, string(output), "clusterName: prod-cluster")
}

func TestFormatConfigOutputText(t *testing.T) {
	cfg := &ConfigObj{
		AccountID:      "account-123",
		CloudAPIURL:    "https://api.example.com",
		CloudReportURL: "https://report.example.com",
	}

	output, err := FormatConfigOutput(cfg, "text", false)
	require.NoError(t, err)

	assert.Contains(t, string(output), "accountID: account-123")
	assert.Contains(t, string(output), "cloudAPIURL: https://api.example.com")
	assert.Contains(t, string(output), "cloudReportURL: https://report.example.com")
}

func TestFormatConfigOutputTextOmitsEmptyValues(t *testing.T) {
	cfg := &ConfigObj{AccountID: "account-123"}

	output, err := FormatConfigOutput(cfg, "text", false)
	require.NoError(t, err)

	assert.Contains(t, string(output), "accountID: account-123")
	assert.NotContains(t, string(output), "accessKey")
	assert.NotContains(t, string(output), "clusterName")
}

func TestFormatConfigOutputUnsupportedFormat(t *testing.T) {
	cfg := &ConfigObj{AccountID: "account-123"}

	_, err := FormatConfigOutput(cfg, "xml", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported output format")
}

func TestFormatConfigOutputJSONIncludesEmptyValuesWhenRequested(t *testing.T) {
	cfg := &ConfigObj{AccountID: "account-123"}

	output, err := FormatConfigOutput(cfg, "json", true)
	require.NoError(t, err)

	assert.Contains(t, string(output), `"accountID": "account-123"`)
	assert.Contains(t, string(output), `"clusterName": ""`)
	assert.Contains(t, string(output), `"accessKey": ""`)
}

func TestFormatConfigOutputYAMLIncludesEmptyValuesWhenRequested(t *testing.T) {
	cfg := &ConfigObj{AccountID: "account-123"}

	output, err := FormatConfigOutput(cfg, "yaml", true)
	require.NoError(t, err)

	assert.Contains(t, string(output), "accountID: account-123")
	assert.Contains(t, string(output), "clusterName: \"\"")
	assert.Contains(t, string(output), "accessKey: \"\"")
}

func TestFormatConfigOutputDefaultFormatIsText(t *testing.T) {
	cfg := &ConfigObj{AccountID: "account-123"}

	output, err := FormatConfigOutput(cfg, "", false)
	require.NoError(t, err)

	assert.Equal(t, "accountID: account-123\n", string(output))
}

func TestFormatConfigOutputNormalizesFormat(t *testing.T) {
	cfg := &ConfigObj{AccountID: "account-123"}

	output, err := FormatConfigOutput(cfg, " YAML ", false)
	require.NoError(t, err)

	assert.Contains(t, string(output), "accountID: account-123")
}

func TestFormatConfigOutputNilConfig(t *testing.T) {
	output, err := FormatConfigOutput(nil, "json", true)
	require.NoError(t, err)

	var payload map[string]string
	require.NoError(t, json.Unmarshal(output, &payload))

	assert.Equal(t, "", payload["accountID"])
	assert.Equal(t, "", payload["clusterName"])
	assert.Equal(t, "", payload["cloudReportURL"])
	assert.Equal(t, "", payload["cloudAPIURL"])
	assert.Equal(t, "", payload["accessKey"])
}

func TestFormatConfigOutputJSONOmitsOnlyEmptyFields(t *testing.T) {
	cfg := &ConfigObj{
		AccountID:   "account-123",
		ClusterName: "prod-cluster",
		AccessKey:   "",
	}

	output, err := FormatConfigOutput(cfg, "json", false)
	require.NoError(t, err)

	var payload map[string]string
	require.NoError(t, json.Unmarshal(output, &payload))

	assert.Equal(t, map[string]string{
		"accountID":   "account-123",
		"clusterName": "prod-cluster",
	}, payload)
}

func TestFormatConfigOutputYAMLParsesAsMap(t *testing.T) {
	cfg := &ConfigObj{
		AccountID:      "account-123",
		CloudAPIURL:    "https://api.example.com",
		CloudReportURL: "https://report.example.com",
	}

	output, err := FormatConfigOutput(cfg, "yaml", false)
	require.NoError(t, err)

	var payload map[string]string
	require.NoError(t, yaml.Unmarshal(output, &payload))

	assert.Equal(t, "account-123", payload["accountID"])
	assert.Equal(t, "https://api.example.com", payload["cloudAPIURL"])
	assert.Equal(t, "https://report.example.com", payload["cloudReportURL"])
	assert.NotContains(t, payload, "accessKey")
}
