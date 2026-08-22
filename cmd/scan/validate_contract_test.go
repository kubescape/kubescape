package scan

import (
	"bytes"
	"context"
	"encoding/json"
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
