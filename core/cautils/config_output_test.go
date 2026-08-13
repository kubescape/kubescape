package cautils

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
