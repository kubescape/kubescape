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
	"github.com/spf13/cobra"
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

func TestValidateContractCommandRejectsNullNamespaces(t *testing.T) {
	path := writeScanContract(t, `
      policy:
        frameworks: [nsa]
      scope:
        excludeNamespaces: [null]`)
	cmd := GetScanCommand(core.NewKubescape(context.Background()))
	output := &bytes.Buffer{}
	cmd.SetOut(output)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"validate-contract", path})
	require.ErrorContains(t, cmd.Execute(), "null entry")
	assert.NotContains(t, output.String(), `is valid`, "an invalid contract must not be reported as valid")
}

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

func TestValidateContractCommandRejectsOutputOverwritingInput(t *testing.T) {
	originalBuildNumber := versioncheck.BuildNumber
	versioncheck.BuildNumber = "v4.1.0"
	t.Cleanup(func() { versioncheck.BuildNumber = originalBuildNumber })

	for _, scenario := range []struct {
		name    string
		format  string
		invalid bool
	}{
		{name: "text", format: "text"},
		{name: "json", format: "json"},
		{name: "sarif", format: "sarif"},
		{name: "invalid contract sarif", format: "sarif", invalid: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			for _, alias := range []string{"same path", "relative path", "output symlink", "input symlink", "hard link"} {
				t.Run(alias, func(t *testing.T) {
					directory := t.TempDir()
					inputPath := filepath.Join(directory, "kubescape.yaml")
					original := []byte(commandContract)
					if scenario.invalid {
						original = bytes.Replace(original, []byte("frameworks"), []byte("frameworkz"), 1)
					}
					require.NoError(t, os.WriteFile(inputPath, original, 0o600))
					outputPath := inputPath
					switch alias {
					case "relative path":
						// Keep input and output in different path forms without changing the working directory.
						workingDirectory, err := os.Getwd()
						require.NoError(t, err)
						outputPath, err = filepath.Rel(workingDirectory, inputPath)
						require.NoError(t, err)
					case "output symlink":
						outputPath = filepath.Join(directory, "output.yaml")
						require.NoError(t, os.Symlink(inputPath, outputPath))
					case "input symlink":
						inputPath = filepath.Join(directory, "input.yaml")
						require.NoError(t, os.Symlink(outputPath, inputPath))
					case "hard link":
						outputPath = filepath.Join(directory, "output.yaml")
						require.NoError(t, os.Link(inputPath, outputPath))
					}

					cmd := GetScanCommand(core.NewKubescape(context.Background()))
					cmd.SetOut(io.Discard)
					cmd.SetErr(io.Discard)
					cmd.SetArgs([]string{"validate-contract", inputPath, "--format", scenario.format, "--output", outputPath})
					require.ErrorContains(t, cmd.Execute(), "would overwrite input contract")

					for _, path := range []string{inputPath, outputPath} {
						contents, err := os.ReadFile(path)
						require.NoError(t, err)
						assert.Equal(t, original, contents, "contract must remain unchanged at %s", path)
					}
				})
			}
		})
	}
}

func TestValidateContractCommandSARIFMissingInputWritesExistingOutput(t *testing.T) {
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "missing.yaml")
	outputPath := filepath.Join(directory, "validation.sarif")
	require.NoError(t, os.WriteFile(outputPath, []byte("previous output"), 0o600))

	cmd := GetScanCommand(core.NewKubescape(context.Background()))
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"validate-contract", inputPath, "--format", "sarif", "--output", outputPath})
	require.ErrorIs(t, cmd.Execute(), os.ErrNotExist)

	contents, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	report := decodeValidateContractSARIF(t, contents)
	run := report["runs"].([]any)[0].(map[string]any)
	assert.Len(t, run["results"].([]any), 1)
	assert.NoFileExists(t, inputPath)
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

func TestValidateContractCommandFormatNormalization(t *testing.T) {
	originalBuildNumber := versioncheck.BuildNumber
	versioncheck.BuildNumber = "v4.1.0"
	t.Cleanup(func() { versioncheck.BuildNumber = originalBuildNumber })

	contractPath := filepath.Join(t.TempDir(), "kubescape.yaml")
	require.NoError(t, os.WriteFile(contractPath, []byte(commandContract), 0o600))

	tests := []struct {
		name       string
		format     string
		wantPrefix string
	}{
		{name: "uppercase JSON", format: "JSON", wantPrefix: "{\n"},
		{name: "uppercase TEXT", format: "TEXT", wantPrefix: `Scan contract "example" is valid`},
		{name: "uppercase SARIF", format: "SARIF", wantPrefix: "{\n"},
		{name: "padded json", format: "  json  ", wantPrefix: "{\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := GetScanCommand(core.NewKubescape(context.Background()))
			output := &bytes.Buffer{}
			cmd.SetOut(output)
			cmd.SetErr(output)
			cmd.SetArgs([]string{"validate-contract", contractPath, "--format", tt.format})
			require.NoError(t, cmd.Execute())
			assert.Contains(t, output.String(), tt.wantPrefix)
		})
	}
}

func TestValidateContractCommandEmptyFormatRejected(t *testing.T) {
	contractPath := filepath.Join(t.TempDir(), "kubescape.yaml")
	require.NoError(t, os.WriteFile(contractPath, []byte(commandContract), 0o600))

	for _, format := range []string{"", "   ", "\t"} {
		cmd := GetScanCommand(core.NewKubescape(context.Background()))
		cmd.SetArgs([]string{"validate-contract", contractPath, "--format", format})
		err := cmd.Execute()
		require.Error(t, err)
		assert.EqualError(t, err, "format cannot be empty, supported formats: text, json, sarif")
	}
}

func TestValidateContractCommandUnsupportedFormatRejectedUpfrontOnInvalidContract(t *testing.T) {
	contractPath := filepath.Join(t.TempDir(), "kubescape.yaml")
	invalid := bytes.Replace([]byte(commandContract), []byte("frameworks"), []byte("frameworkz"), 1)
	require.NoError(t, os.WriteFile(contractPath, invalid, 0o600))

	cmd := GetScanCommand(core.NewKubescape(context.Background()))
	cmd.SetArgs([]string{"validate-contract", contractPath, "--format", "xml"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.EqualError(t, err, `unsupported format "xml", supported: text, json, sarif`)
}

func TestValidateContractCommandSARIFUppercaseOnInvalidContract(t *testing.T) {
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
	cmd.SetArgs([]string{"validate-contract", contractPath, "--format", "SARIF"})
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
}

func TestValidateContractCommandRejectsPaddedAndWhitespaceContractNames(t *testing.T) {
	originalBuildNumber := versioncheck.BuildNumber
	versioncheck.BuildNumber = "v4.1.0"
	t.Cleanup(func() { versioncheck.BuildNumber = originalBuildNumber })

	contractPath := filepath.Join(t.TempDir(), "kubescape.yaml")
	require.NoError(t, os.WriteFile(contractPath, []byte(commandContract), 0o600))

	tests := []struct {
		name         string
		contractName string
		wantErr      string
	}{
		{
			name:         "padded contract name is rejected and not trimmed",
			contractName: " ci ",
			wantErr:      `contract " ci " does not exist`,
		},
		{
			name:         "whitespace-only contract name is rejected and does not fall back to default",
			contractName: "   ",
			wantErr:      `contract "   " does not exist`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// validate-contract path
			validateCmd := GetScanCommand(core.NewKubescape(context.Background()))
			validateCmd.SetArgs([]string{"validate-contract", contractPath, "--contract", tt.contractName})
			validateErr := validateCmd.Execute()
			require.Error(t, validateErr)
			assert.Contains(t, validateErr.Error(), tt.wantErr)

			// scan path (verifying parity: validation does not select a different contract from the scan path)
			scanCmd := GetScanCommand(core.NewKubescape(context.Background()))
			root := &cobra.Command{Use: "kubescape", SilenceErrors: true, SilenceUsage: true}
			root.AddCommand(scanCmd)
			root.SetArgs([]string{"scan", ".", "--scan-contract", contractPath, "--contract", tt.contractName})
			scanErr := root.Execute()
			require.Error(t, scanErr)
			assert.Contains(t, scanErr.Error(), tt.wantErr)
		})
	}
}

func decodeValidateContractSARIF(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var report map[string]any
	require.NoError(t, json.Unmarshal(data, &report))
	return report
}
