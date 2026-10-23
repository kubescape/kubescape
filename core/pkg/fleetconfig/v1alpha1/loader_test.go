package v1alpha1

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fullConfig = `apiVersion: config.kubescape.io/v1alpha1
kind: FleetConfig
metadata:
  name: production
spec:
  contexts: [prod, staging, dr]
  output: reports/report.json
  fleetReport: reports/fleet.json
  referenceCluster: prod
  retries: 0
`

// TestLoadReadsEverySetting pins that each field lands in the spec, including an explicit zero.
func TestLoadReadsEverySetting(t *testing.T) {
	document, err := Load([]byte(fullConfig))
	require.NoError(t, err)

	spec := document.Spec
	assert.Equal(t, "production", document.Metadata.Name)
	require.NotNil(t, spec.Contexts)
	assert.Equal(t, ContextList{"prod", "staging", "dr"}, *spec.Contexts)
	assert.Equal(t, "reports/report.json", *spec.Output)
	assert.Equal(t, "reports/fleet.json", *spec.FleetReport)
	assert.Equal(t, "prod", *spec.ReferenceCluster)
	require.NotNil(t, spec.Retries, "retries: 0 is a setting, not an omission")
	assert.Equal(t, Count(0), *spec.Retries)
}

// TestLoadLeavesOmittedSettingsUnset pins that a field the file does not mention stays nil, so the flag default is kept.
func TestLoadLeavesOmittedSettingsUnset(t *testing.T) {
	document, err := Load([]byte("apiVersion: config.kubescape.io/v1alpha1\nkind: FleetConfig\nspec:\n  contexts: [prod]\n"))
	require.NoError(t, err)

	assert.Nil(t, document.Spec.Output)
	assert.Nil(t, document.Spec.FleetReport)
	assert.Nil(t, document.Spec.ReferenceCluster)
	assert.Nil(t, document.Spec.Retries)
}

// TestLoadRejectsInvalidDocuments pins the errors for files that are not a usable fleet config.
func TestLoadRejectsInvalidDocuments(t *testing.T) {
	tests := map[string]struct {
		contents string
		want     string
	}{
		"empty":               {contents: "  \n", want: "document is empty"},
		"wrong apiVersion":    {contents: "apiVersion: config.kubescape.io/v2\nkind: FleetConfig\n", want: `unsupported apiVersion "config.kubescape.io/v2"`},
		"a scan contract":     {contents: "apiVersion: config.kubescape.io/v1alpha1\nkind: ScanContract\nspec:\n  contracts: {}\n", want: `unsupported kind "ScanContract"`},
		"misspelt field":      {contents: "apiVersion: config.kubescape.io/v1alpha1\nkind: FleetConfig\nspec:\n  fleetreport: fleet.json\n", want: "field fleetreport not found"},
		"null context":        {contents: "apiVersion: config.kubescape.io/v1alpha1\nkind: FleetConfig\nspec:\n  contexts: [prod, null, staging]\n", want: "a context in the list is null"},
		"tilde context":       {contents: "apiVersion: config.kubescape.io/v1alpha1\nkind: FleetConfig\nspec:\n  contexts:\n    - prod\n    - ~\n", want: "line 6: a context in the list is null"},
		"empty context":       {contents: "apiVersion: config.kubescape.io/v1alpha1\nkind: FleetConfig\nspec:\n  contexts: [prod, \"\"]\n", want: "line 4: a context in the list is empty"},
		"blank context":       {contents: "apiVersion: config.kubescape.io/v1alpha1\nkind: FleetConfig\nspec:\n  contexts:\n    - prod\n    - \"   \"\n", want: "line 6: a context in the list is empty"},
		"contexts not a list": {contents: "apiVersion: config.kubescape.io/v1alpha1\nkind: FleetConfig\nspec:\n  contexts: prod\n", want: "contexts must be a list"},
		"retries as words":    {contents: "apiVersion: config.kubescape.io/v1alpha1\nkind: FleetConfig\nspec:\n  retries: two\n", want: `"two" is not a whole number`},
		"fractional retries":  {contents: "apiVersion: config.kubescape.io/v1alpha1\nkind: FleetConfig\nspec:\n  retries: 1.5\n", want: `"1.5" is not a whole number`},
		"negative fraction":   {contents: "apiVersion: config.kubescape.io/v1alpha1\nkind: FleetConfig\nspec:\n  retries: -0.5\n", want: `"-0.5" is not a whole number`},
		"retries as a list":   {contents: "apiVersion: config.kubescape.io/v1alpha1\nkind: FleetConfig\nspec:\n  retries: [2]\n", want: "is not a whole number"},
		"two documents":       {contents: fullConfig + "---\n" + fullConfig, want: "exactly one YAML document"},
		"not yaml at all":     {contents: "apiVersion: [\n", want: "decode version envelope"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Load([]byte(tt.contents))
			assert.ErrorContains(t, err, tt.want)
		})
	}
}

// TestLoadFileNamesTheFile pins that errors say which file was wrong.
func TestLoadFileNamesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.yaml")
	require.NoError(t, os.WriteFile(path, []byte("apiVersion: config.kubescape.io/v1alpha1\nkind: Fleet\n"), 0o600))

	_, err := LoadFile(path)
	assert.ErrorContains(t, err, path)

	_, err = LoadFile(filepath.Join(t.TempDir(), "missing.yaml"))
	assert.ErrorContains(t, err, "read fleet config")
}
