package scan

import (
	"bytes"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContractSymlinkParentPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink parent traversal uses different path semantics on Windows")
	}

	workspace := t.TempDir()
	t.Chdir(workspace)
	outside := t.TempDir()
	for link, target := range map[string]string{
		"link":      filepath.Join(workspace, "target", "child"),
		"outside":   filepath.Join(outside, "child"),
		"special":   filepath.Join(workspace, "config #?%", "child"),
		"backslash": filepath.Join(outside, `config\prod`, "child"),
	} {
		require.NoError(t, os.MkdirAll(target, 0o700))
		require.NoError(t, os.Symlink(target, link))
	}

	document := strings.Replace(commandContract, "minimumKubescapeVersion: v4.0.0", "minimumKubescapeVersion: v0.0.1", 1)
	require.NoError(t, os.WriteFile("contract.yaml", []byte(document), 0o600))
	document = strings.Replace(document, "name: example", "name: intended-ci", 1)
	document = strings.Replace(document, "defaultContract: developer", "defaultContract: ci", 1)

	for _, scenario := range []struct {
		name   string
		path   string
		target string
		source string
	}{
		{"relative", "link/../contract.yaml", "target/contract.yaml", "target/contract.yaml"},
		{"absolute", workspace + "/link/../contract.yaml", "target/contract.yaml", "target/contract.yaml"},
		{"external", "outside/../contract.yaml", filepath.Join(outside, "contract.yaml"), "external"},
		{"special characters", "special/../contract.yaml", "config #?%/contract.yaml", "config #?%/contract.yaml"},
		{"external backslash", "backslash/contract.yaml", filepath.Join(outside, `config\prod`, "child", "contract.yaml"), "external"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			require.NoError(t, os.WriteFile(scenario.target, []byte(document), 0o600))
			ks := &contractCaptureKubescape{}
			cmd := GetScanCommand(ks)
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs([]string{"framework", "nsa", ".", "--scan-contract", scenario.path})
			require.ErrorIs(t, cmd.Execute(), errContractScanReached)
			require.NotNil(t, ks.captured)
			require.NotNil(t, ks.captured.ScanContract)
			assert.Equal(t, "intended-ci", ks.captured.ScanContract.Name)
			assert.Equal(t, "ci", ks.captured.ScanContract.Contract)
			assert.Equal(t, scenario.source, ks.captured.ScanContract.Source)

			invalid := strings.Replace(document, "frameworks:", "frameworkz:", 1)
			require.NoError(t, os.WriteFile(scenario.target, []byte(invalid), 0o600))
			output := &bytes.Buffer{}
			cmd = GetScanCommand(ks)
			cmd.SetOut(output)
			cmd.SetErr(io.Discard)
			cmd.SetArgs([]string{"validate-contract", scenario.path, "--format", "sarif"})
			require.ErrorContains(t, cmd.Execute(), "field frameworkz not found")
			report := decodeValidateContractSARIF(t, output.Bytes())
			run := report["runs"].([]any)[0].(map[string]any)
			artifact := run["artifacts"].([]any)[0].(map[string]any)
			artifactURI := artifact["location"].(map[string]any)["uri"].(string)
			result := run["results"].([]any)[0].(map[string]any)
			location := result["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
			assert.Equal(t, artifactURI, location["artifactLocation"].(map[string]any)["uri"])
			parsed, err := url.Parse(artifactURI)
			require.NoError(t, err)
			assert.Empty(t, parsed.Fragment)
			assert.Empty(t, parsed.RawQuery)
			if scenario.source == "external" {
				assert.Equal(t, "file", parsed.Scheme)
			} else {
				assert.Empty(t, parsed.Scheme)
			}
			base := &url.URL{Scheme: "file", Path: filepath.ToSlash(workspace) + "/"}
			resolved := base.ResolveReference(parsed)
			uriInfo, err := os.Stat(filepath.FromSlash(resolved.Path))
			require.NoError(t, err)
			targetInfo, err := os.Stat(scenario.target)
			require.NoError(t, err)
			assert.True(t, os.SameFile(uriInfo, targetInfo), "SARIF URI %q must identify the validated contract", artifactURI)
		})
	}
}
