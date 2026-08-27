package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/kubescape/v4/core/core"
	contractv1alpha1 "github.com/kubescape/kubescape/v4/core/pkg/scancontract/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const commandContract = `
apiVersion: config.kubescape.io/v1alpha1
kind: ScanContract
metadata:
  name: example
spec:
  minimumKubescapeVersion: v4.0.0
  defaultContract: developer
  contracts:
    developer:
      policy:
        frameworks: [nsa]
      output:
        formats: [pretty-printer]
    ci:
      failure:
        severityAtLeast: high
        coverageBelow: 95
      output:
        formats: [json]
`

func TestValidateContractCommand(t *testing.T) {
	originalBuildNumber := versioncheck.BuildNumber
	versioncheck.BuildNumber = "v4.1.0"
	t.Cleanup(func() { versioncheck.BuildNumber = originalBuildNumber })

	contractPath := filepath.Join(t.TempDir(), "kubescape.yaml")
	require.NoError(t, os.WriteFile(contractPath, []byte(commandContract), 0o600))

	cmd := GetScanCommand(core.NewKubescape(context.Background()))
	output := &bytes.Buffer{}
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"validate-contract", contractPath, "--contract", "ci", "--format", "json"})
	require.NoError(t, cmd.Execute())

	var selected contractv1alpha1.SelectedContract
	require.NoError(t, json.Unmarshal(output.Bytes(), &selected))
	assert.Equal(t, "ci", selected.ContractName)
	assert.Regexp(t, `^sha256:[0-9a-f]{64}$`, selected.ContractDigest)
}

func TestValidateContractCommandAcceptsDevelopmentBuild(t *testing.T) {
	originalBuildNumber := versioncheck.BuildNumber
	versioncheck.BuildNumber = "dev"
	t.Cleanup(func() { versioncheck.BuildNumber = originalBuildNumber })

	contractPath := filepath.Join(t.TempDir(), "kubescape.yaml")
	require.NoError(t, os.WriteFile(contractPath, []byte(commandContract), 0o600))

	cmd := GetScanCommand(core.NewKubescape(context.Background()))
	output := &bytes.Buffer{}
	cmd.SetOut(output)
	cmd.SetArgs([]string{"validate-contract", contractPath})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, output.String(), `Scan contract "example" is valid`)
}

func TestValidateContractCommandWritesOutputFile(t *testing.T) {
	originalBuildNumber := versioncheck.BuildNumber
	versioncheck.BuildNumber = "v4.1.0"
	t.Cleanup(func() { versioncheck.BuildNumber = originalBuildNumber })

	temporaryDirectory := t.TempDir()
	contractPath := filepath.Join(temporaryDirectory, "kubescape.yaml")
	outputPath := filepath.Join(temporaryDirectory, "selected.json")
	require.NoError(t, os.WriteFile(contractPath, []byte(commandContract), 0o600))

	cmd := GetScanCommand(core.NewKubescape(context.Background()))
	cmd.SetArgs([]string{"validate-contract", contractPath, "--format", "json", "--output", outputPath})
	require.NoError(t, cmd.Execute())

	contents, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	var selected contractv1alpha1.SelectedContract
	require.NoError(t, json.Unmarshal(contents, &selected))
	assert.Equal(t, "developer", selected.ContractName)
}

func TestValidateContractCommandReportsStrictErrors(t *testing.T) {
	originalBuildNumber := versioncheck.BuildNumber
	versioncheck.BuildNumber = "v4.1.0"
	t.Cleanup(func() { versioncheck.BuildNumber = originalBuildNumber })

	contractPath := filepath.Join(t.TempDir(), "kubescape.yaml")
	invalid := bytes.Replace([]byte(commandContract), []byte("frameworks"), []byte("frameworkz"), 1)
	require.NoError(t, os.WriteFile(contractPath, invalid, 0o600))

	cmd := GetScanCommand(core.NewKubescape(context.Background()))
	cmd.SetArgs([]string{"validate-contract", contractPath})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "field frameworkz not found")
}

func TestValidateContractCommandSARIFValidContract(t *testing.T) {
	originalBuildNumber := versioncheck.BuildNumber
	versioncheck.BuildNumber = "v4.1.0"
	t.Cleanup(func() { versioncheck.BuildNumber = originalBuildNumber })

	contractPath := filepath.Join(t.TempDir(), "kubescape.yaml")
	require.NoError(t, os.WriteFile(contractPath, []byte(commandContract), 0o600))

	cmd := GetScanCommand(core.NewKubescape(context.Background()))
	output := &bytes.Buffer{}
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"validate-contract", contractPath, "--format", "sarif"})
	require.NoError(t, cmd.Execute())

	report := decodeValidateContractSARIF(t, output.Bytes())
	assert.Equal(t, "2.1.0", report["version"])
	runs := report["runs"].([]any)
	require.Len(t, runs, 1)
	run := runs[0].(map[string]any)
	assert.Empty(t, run["results"].([]any))

	invocations := run["invocations"].([]any)
	require.Len(t, invocations, 1)
	invocation := invocations[0].(map[string]any)
	assert.Equal(t, true, invocation["executionSuccessful"])
	assert.Equal(t, float64(0), invocation["exitCode"])

	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	assert.Equal(t, "Kubescape", driver["name"])
	rules := driver["rules"].([]any)
	require.Len(t, rules, 1)
	assert.Equal(t, "kubescape.scan-contract.valid", rules[0].(map[string]any)["id"])
}

func TestValidateContractCommandSARIFInvalidContract(t *testing.T) {
	originalBuildNumber := versioncheck.BuildNumber
	versioncheck.BuildNumber = "v4.1.0"
	t.Cleanup(func() { versioncheck.BuildNumber = originalBuildNumber })

	contractPath := filepath.Join(t.TempDir(), "kubescape.yaml")
	invalid := bytes.Replace([]byte(commandContract), []byte("frameworks"), []byte("frameworkz"), 1)
	require.NoError(t, os.WriteFile(contractPath, invalid, 0o600))

	cmd := GetScanCommand(core.NewKubescape(context.Background()))
	output := &bytes.Buffer{}
	cmd.SetOut(output)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"validate-contract", contractPath, "--format", "sarif"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "field frameworkz not found")

	report := decodeValidateContractSARIF(t, output.Bytes())
	run := report["runs"].([]any)[0].(map[string]any)
	results := run["results"].([]any)
	require.Len(t, results, 1)
	result := results[0].(map[string]any)
	assert.Equal(t, "kubescape.scan-contract.valid", result["ruleId"])
	assert.Equal(t, "error", result["level"])
	assert.Contains(t, result["message"].(map[string]any)["text"], "field frameworkz not found")

	invocation := run["invocations"].([]any)[0].(map[string]any)
	assert.Equal(t, false, invocation["executionSuccessful"])
	assert.Equal(t, float64(1), invocation["exitCode"])
}

func TestValidateContractCommandSARIFRelativizesAbsoluteContractPath(t *testing.T) {
	originalBuildNumber := versioncheck.BuildNumber
	versioncheck.BuildNumber = "v4.1.0"
	t.Cleanup(func() { versioncheck.BuildNumber = originalBuildNumber })

	workspace := t.TempDir()
	contractPath := filepath.Join(workspace, "configs", "kubescape.yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(contractPath), 0o700))
	invalid := bytes.Replace([]byte(commandContract), []byte("frameworks"), []byte("frameworkz"), 1)
	require.NoError(t, os.WriteFile(contractPath, invalid, 0o600))

	originalWorkingDirectory, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(workspace))
	t.Cleanup(func() {
		require.NoError(t, os.Chdir(originalWorkingDirectory))
	})

	cmd := GetScanCommand(core.NewKubescape(context.Background()))
	output := &bytes.Buffer{}
	cmd.SetOut(output)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"validate-contract", contractPath, "--format", "sarif"})
	err = cmd.Execute()
	require.Error(t, err)

	report := decodeValidateContractSARIF(t, output.Bytes())
	run := report["runs"].([]any)[0].(map[string]any)
	artifacts := run["artifacts"].([]any)
	require.Len(t, artifacts, 1)
	artifactLocation := artifacts[0].(map[string]any)["location"].(map[string]any)
	assert.Equal(t, "configs/kubescape.yaml", artifactLocation["uri"])

	results := run["results"].([]any)
	require.Len(t, results, 1)
	locations := results[0].(map[string]any)["locations"].([]any)
	physicalLocation := locations[0].(map[string]any)["physicalLocation"].(map[string]any)
	resultArtifactLocation := physicalLocation["artifactLocation"].(map[string]any)
	assert.Equal(t, "configs/kubescape.yaml", resultArtifactLocation["uri"])
}

func TestValidateContractCommandSARIFWritesOutputFileOnError(t *testing.T) {
	originalBuildNumber := versioncheck.BuildNumber
	versioncheck.BuildNumber = "v4.1.0"
	t.Cleanup(func() { versioncheck.BuildNumber = originalBuildNumber })

	temporaryDirectory := t.TempDir()
	contractPath := filepath.Join(temporaryDirectory, "kubescape.yaml")
	outputPath := filepath.Join(temporaryDirectory, "contract.sarif")
	invalid := bytes.Replace([]byte(commandContract), []byte("frameworks"), []byte("frameworkz"), 1)
	require.NoError(t, os.WriteFile(contractPath, invalid, 0o600))

	cmd := GetScanCommand(core.NewKubescape(context.Background()))
	cmd.SetArgs([]string{"validate-contract", contractPath, "--format", "sarif", "--output", outputPath})
	err := cmd.Execute()
	require.Error(t, err)

	contents, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	report := decodeValidateContractSARIF(t, contents)
	run := report["runs"].([]any)[0].(map[string]any)
	assert.Len(t, run["results"].([]any), 1)
}

func TestValidateContractCommandUnsupportedFormatMentionsSARIF(t *testing.T) {
	contractPath := filepath.Join(t.TempDir(), "kubescape.yaml")
	require.NoError(t, os.WriteFile(contractPath, []byte(commandContract), 0o600))

	cmd := GetScanCommand(core.NewKubescape(context.Background()))
	cmd.SetArgs([]string{"validate-contract", contractPath, "--format", "xml"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.EqualError(t, err, `unsupported format "xml", supported: text, json, sarif`)
}

func decodeValidateContractSARIF(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var report map[string]any
	require.NoError(t, json.Unmarshal(data, &report))
	return report
}
