package scan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClusterScanSARIF pins that a live cluster scan can write SARIF, alone and
// next to JSON, and that each finding on a resource read from the cluster carries
// the virtual cluster/<namespace>/<kind>/<name>.yaml location the SARIF printer
// gives it (kubescape/kubescape#5244).
func TestClusterScanSARIF(t *testing.T) {
	for _, tc := range []struct {
		name    string
		formats string
		output  string
		sarif   string
		json    string
	}{
		{name: "sarif", formats: "sarif", output: "report.sarif", sarif: "report.sarif"},
		{name: "json and sarif", formats: "json,sarif", output: "report", sarif: "report.sarif", json: "report.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := newFakeAPIServer(t, 0, false)
			dir := prepareClusterScan(t, server.URL)

			policies := filepath.Join("..", "..", "core", "cautils", "getter", "testdata")
			// C-0017 (immutable container filesystem) fails the fake cluster's
			// default/web pod, whose container has no securityContext.
			args := []string{
				"control", "C-0017",
				"--format=" + tc.formats, "--output=" + filepath.Join(dir, tc.output),
				"--keep-local", "--use-from=" + filepath.Join(policies, "NSA.json"),
				"--controls-config=" + filepath.Join(policies, "controls-inputs.json"),
				"--exceptions=" + filepath.Join(policies, "exceptions.json"),
			}
			var err error
			captureStdout(t, func() {
				cmd := GetScanCommand(core.NewKubescape(context.Background()))
				cmd.SilenceUsage = true
				cmd.SilenceErrors = true
				cmd.SetArgs(args)
				err = cmd.Execute()
			})
			require.NoError(t, err)
			assert.True(t, server.asked("/api/v1/pods"), "the scan must read the pods from the cluster")

			uris := sarifResultURIs(t, filepath.Join(dir, tc.sarif))
			assert.Contains(t, uris["C-0017"], "cluster/default/pod/web.yaml")

			if tc.json != "" {
				contents, err := os.ReadFile(filepath.Join(dir, tc.json))
				require.NoError(t, err, "the JSON report is written next to the SARIF one")
				assert.True(t, json.Valid(contents))
			}
		})
	}
}

// prepareClusterScan points a plain (non-fleet) scan at the API server through
// a kubeconfig whose current context is that server, and returns a scratch
// directory for the reports. The context has a name of its own: the fleet E2E
// tests name theirs "prod", and sharing that name made them dial this test's
// stopped server.
func prepareClusterScan(t *testing.T, serverURL string) string {
	t.Helper()
	dir := t.TempDir()
	kubeconfig := filepath.Join(dir, "kubeconfig")
	content := "apiVersion: v1\nkind: Config\ncurrent-context: cluster-sarif\n" +
		"clusters:\n- name: cluster-sarif\n  cluster:\n    server: " + serverURL + "\n" +
		"contexts:\n- name: cluster-sarif\n  context:\n    cluster: cluster-sarif\n    user: user\n" +
		"users:\n- name: user\n  user:\n    token: e2e-token\n"
	require.NoError(t, os.WriteFile(kubeconfig, []byte(content), 0o600))
	t.Setenv("KUBECONFIG", kubeconfig)
	t.Setenv("HOME", t.TempDir())
	// Read the config before IsConnectedToCluster, which loads this kubeconfig
	// into it when it is unset.
	previousConfig := k8sinterface.K8SConfig
	previousConnected := k8sinterface.IsConnectedToCluster()
	t.Cleanup(func() {
		// Naming the context resets the loaded config and the connection state, so
		// they are put back after it. Restore no explicit context, not the name
		// the kubeconfig resolved to, which later tests' kubeconfigs may not have.
		// The scan also caches the parsed kubeconfig, which a context name that
		// is already empty does not clear.
		k8sinterface.SetClusterContextName("")
		k8sinterface.SetClientConfigAPI(nil)
		k8sinterface.K8SConfig = previousConfig
		k8sinterface.SetConnectedToCluster(previousConnected)
	})
	// Another test may have left a context name that this kubeconfig does not
	// have, a loaded or parsed kubeconfig, or a failed connection. Start from
	// none of them.
	k8sinterface.SetClusterContextName("")
	k8sinterface.SetClientConfigAPI(nil)
	k8sinterface.K8SConfig = nil
	k8sinterface.SetConnectedToCluster(true)
	return dir
}

// sarifResultURIs reads a SARIF report and returns, for each rule ID, the
// artifact URIs of its results' physical locations.
func sarifResultURIs(t *testing.T, path string) map[string][]string {
	t.Helper()
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	var report struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(contents, &report))
	uris := make(map[string][]string)
	for _, run := range report.Runs {
		for _, result := range run.Results {
			for _, location := range result.Locations {
				uris[result.RuleID] = append(uris[result.RuleID], location.PhysicalLocation.ArtifactLocation.URI)
			}
		}
	}
	require.NotEmpty(t, uris, "the SARIF report has no results: %s", strings.TrimSpace(string(contents)))
	return uris
}
