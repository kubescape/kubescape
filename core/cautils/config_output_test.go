package cautils

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/jwalton/gchalk"
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

	var payload map[string]string
	require.NoError(t, yaml.Unmarshal(output, &payload))

	assert.Equal(t, "account-123", payload["accountID"])
	assert.Equal(t, "****cret", payload["accessKey"])
	assert.Equal(t, "prod-cluster", payload["clusterName"])
}

func TestFormatConfigOutputText(t *testing.T) {
	t.Setenv("FORCE_COLOR", "0")
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
	t.Setenv("FORCE_COLOR", "0")
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
	t.Setenv("FORCE_COLOR", "0")
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

func TestFormatConfigOutputMasksAccessKey(t *testing.T) {
	t.Setenv("FORCE_COLOR", "0")
	const accessKey = "test-access-key-1234"
	cfg := &ConfigObj{AccountID: "account-123", AccessKey: accessKey}

	for _, format := range []string{"text", "json", "yaml"} {
		t.Run(format, func(t *testing.T) {
			output, err := FormatConfigOutput(cfg, format, false)
			require.NoError(t, err)

			assert.NotContains(t, string(output), accessKey)
			assert.Contains(t, string(output), "****1234")
			assert.Contains(t, string(output), "account-123")
		})
	}
}

func TestFormatConfigOutputMasksShortAccessKeyInFull(t *testing.T) {
	t.Setenv("FORCE_COLOR", "0")
	for _, accessKey := range []string{"k", "12345678"} {
		t.Run(accessKey, func(t *testing.T) {
			output, err := FormatConfigOutput(&ConfigObj{AccessKey: accessKey}, "text", false)
			require.NoError(t, err)

			assert.Equal(t, "accessKey: ****\n", string(output))
		})
	}
}

func TestFormatConfigOutputKeepsEmptyAccessKeyEmpty(t *testing.T) {
	output, err := FormatConfigOutput(&ConfigObj{AccountID: "account-123"}, "json", true)
	require.NoError(t, err)

	var payload map[string]string
	require.NoError(t, json.Unmarshal(output, &payload))

	accessKey, ok := payload["accessKey"]
	require.True(t, ok, "--include-empty must still render the accessKey field")
	assert.Equal(t, "", accessKey)
}

func TestFormatConfigFieldOutput(t *testing.T) {
	field := ConfigOutputField{Name: "accountID", Value: "test-account"}

	tests := []struct {
		name    string
		format  string
		want    string
		wantErr bool
	}{
		{
			name:   "Text format",
			format: "text",
			want:   "test-account\n",
		},
		{
			name:   "Default format",
			format: "",
			want:   "test-account\n",
		},
		{
			name:   "JSON format",
			format: "json",
			want:   "{\n  \"accountID\": \"test-account\"\n}",
		},
		{
			name:   "YAML format",
			format: "yaml",
			want:   "accountID: test-account\n",
		},
		{
			name:    "Unsupported format",
			format:  "xml",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FormatConfigFieldOutput(field, tt.format)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, string(got))
			}
		})
	}
}

func TestFormatConfigOutputText_WithColor(t *testing.T) {
	if orig, ok := os.LookupEnv("NO_COLOR"); ok {
		os.Unsetenv("NO_COLOR")
		t.Cleanup(func() {
			_ = os.Setenv("NO_COLOR", orig)
		})
	}
	t.Setenv("FORCE_COLOR", "1")
	prevLevel := gchalk.GetLevel()
	gchalk.SetLevel(gchalk.LevelAnsi16m)
	defer gchalk.SetLevel(prevLevel)

	cfg := &ConfigObj{
		AccountID: "account-123",
		AccessKey: "test-access-key-1234",
	}

	output, err := FormatConfigOutput(cfg, "text", true)
	require.NoError(t, err)

	outStr := string(output)

	// Key names in bright cyan bold
	assert.Contains(t, outStr, gchalk.WithBrightCyan().Bold("accountID"))
	assert.Contains(t, outStr, gchalk.WithBrightCyan().Bold("accessKey"))
	assert.Contains(t, outStr, gchalk.WithBrightCyan().Bold("clusterName"))

	// Normal value in bright white
	assert.Contains(t, outStr, gchalk.BrightWhite("account-123"))

	// Masked secret in yellow
	assert.Contains(t, outStr, gchalk.Yellow("****1234"))

	// Empty value in yellow (<not set>)
	assert.Contains(t, outStr, gchalk.Yellow("<not set>"))
}

func TestFormatConfigOutputText_NoColorPrecedence(t *testing.T) {
	t.Setenv("FORCE_COLOR", "1")
	t.Setenv("NO_COLOR", "1")
	prevLevel := gchalk.GetLevel()
	gchalk.SetLevel(gchalk.LevelAnsi16m)
	defer gchalk.SetLevel(prevLevel)

	cfg := &ConfigObj{
		AccountID: "account-123",
		AccessKey: "test-access-key-1234",
	}

	output, err := FormatConfigOutput(cfg, "text", true)
	require.NoError(t, err)

	outStr := string(output)
	// Zero ANSI codes must be emitted
	assert.NotContains(t, outStr, "\x1b[", "NO_COLOR must ensure zero ANSI escape sequences")
	assert.Contains(t, outStr, "accountID: account-123")
	assert.Contains(t, outStr, "accessKey: ****1234")
	assert.Contains(t, outStr, "clusterName: <not set>")
}

func TestFormatConfigOutput_ExportPathsHaveZeroANSI(t *testing.T) {
	if orig, ok := os.LookupEnv("NO_COLOR"); ok {
		os.Unsetenv("NO_COLOR")
		t.Cleanup(func() {
			_ = os.Setenv("NO_COLOR", orig)
		})
	}
	t.Setenv("FORCE_COLOR", "1")
	prevLevel := gchalk.GetLevel()
	gchalk.SetLevel(gchalk.LevelAnsi16m)
	defer gchalk.SetLevel(prevLevel)

	cfg := &ConfigObj{
		AccountID: "account-123",
		AccessKey: "test-access-key-1234",
	}

	// JSON output must have zero ANSI
	jsonOut, err := FormatConfigOutput(cfg, "json", true)
	require.NoError(t, err)
	assert.NotContains(t, string(jsonOut), "\x1b[", "JSON output must have zero ANSI codes")

	// YAML output must have zero ANSI
	yamlOut, err := FormatConfigOutput(cfg, "yaml", true)
	require.NoError(t, err)
	assert.NotContains(t, string(yamlOut), "\x1b[", "YAML output must have zero ANSI codes")
}

func TestFormatConfigOutputText_EmptyNoColorTreatedAsUnset(t *testing.T) {
	if orig, ok := os.LookupEnv("NO_COLOR"); ok {
		t.Cleanup(func() {
			_ = os.Setenv("NO_COLOR", orig)
		})
	}
	t.Setenv("NO_COLOR", "")
	t.Setenv("FORCE_COLOR", "1")
	prevLevel := gchalk.GetLevel()
	gchalk.SetLevel(gchalk.LevelAnsi16m)
	defer gchalk.SetLevel(prevLevel)

	cfg := &ConfigObj{
		AccountID: "account-123",
	}

	output, err := FormatConfigOutput(cfg, "text", false)
	require.NoError(t, err)

	outStr := string(output)
	assert.Contains(t, outStr, gchalk.WithBrightCyan().Bold("accountID"))
	assert.Contains(t, outStr, gchalk.BrightWhite("account-123"))
}
