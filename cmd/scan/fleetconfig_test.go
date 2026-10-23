package scan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fleetSettings is what one context's scan was given, as far as the fleet flags decide it.
type fleetSettings struct {
	Context          string
	KubeContexts     []string
	Output           string
	FleetReport      string
	ReferenceCluster string
	Retries          int
}

// settingsRecorder is a kubescape whose every scan records its fleet settings and fails, so no cluster is needed.
type settingsRecorder struct {
	mocks.MockIKubescape
	seen []fleetSettings
}

// ScanContext records the settings the scan of one context was given.
func (r *settingsRecorder) ScanContext(_ context.Context, scanInfo *cautils.ScanInfo, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	r.seen = append(r.seen, fleetSettings{
		Context:          scanInfo.GetClusterContextName(),
		KubeContexts:     scanInfo.KubeContexts,
		Output:           scanInfo.Output,
		FleetReport:      scanInfo.FleetReport,
		ReferenceCluster: scanInfo.ReferenceCluster,
		Retries:          scanInfo.KubeContextRetries,
	})
	return nil, errors.New("scan reached")
}

// runScan runs the real scan command with args and returns what each context's scan was given.
func runScan(t *testing.T, args ...string) ([]fleetSettings, error) {
	t.Helper()
	recorder := &settingsRecorder{}
	cmd := GetScanCommand(recorder)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs(args)
	err := cmd.Execute()
	return recorder.seen, err
}

// writeFleetConfig writes a fleet config with the given spec and returns its path.
func writeFleetConfig(t *testing.T, spec string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fleet.yaml")
	require.NoError(t, os.WriteFile(path, []byte("apiVersion: config.kubescape.io/v1alpha1\nkind: FleetConfig\nspec:\n"+spec), 0o600))
	return path
}

// TestFleetConfigMatchesTheFlags pins that a fleet config and the same settings as flags produce identical scans.
func TestFleetConfigMatchesTheFlags(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "report.json")
	fleetReport := filepath.Join(dir, "fleet.json")

	fromFlags, flagsErr := runScan(t, "framework", "nsa",
		"--kube-contexts=prod,staging", "--output="+output, "--fleet-report="+fleetReport,
		"--reference-cluster=prod", "--retries=0")
	fromFile, fileErr := runScan(t, "framework", "nsa", "--fleet-config="+writeFleetConfig(t,
		"  contexts: [prod, staging]\n  output: "+output+"\n  fleetReport: "+fleetReport+"\n  referenceCluster: prod\n  retries: 0\n"))

	require.Len(t, fromFlags, 2, "both contexts are scanned")
	assert.Equal(t, fromFlags, fromFile)
	assert.Equal(t, flagsErr.Error(), fileErr.Error())
}

// TestFleetConfigGivesWayToFlags pins that every flag on the command line overrides the same setting in the file.
func TestFleetConfigGivesWayToFlags(t *testing.T) {
	dir := t.TempDir()
	path := writeFleetConfig(t, "  contexts: [prod, staging]\n  output: "+filepath.Join(dir, "file.json")+
		"\n  fleetReport: "+filepath.Join(dir, "file-fleet.json")+"\n  referenceCluster: prod\n  retries: 5\n")

	t.Run("settings", func(t *testing.T) {
		seen, _ := runScan(t, "framework", "nsa", "--fleet-config="+path,
			"--output="+filepath.Join(dir, "flag.json"), "--fleet-report="+filepath.Join(dir, "flag-fleet.json"),
			"--reference-cluster=staging", "--retries=0")

		require.Len(t, seen, 2, "the contexts still come from the file")
		assert.Equal(t, filepath.Join(dir, "flag.prod.json"), seen[0].Output)
		assert.Equal(t, filepath.Join(dir, "flag-fleet.json"), seen[0].FleetReport)
		assert.Equal(t, "staging", seen[0].ReferenceCluster)
		assert.Zero(t, seen[0].Retries, "an explicit --retries 0 beats the file")
	})

	t.Run("contexts", func(t *testing.T) {
		seen, _ := runScan(t, "framework", "nsa", "--fleet-config="+path,
			"--kube-contexts=staging,prod", "--reference-cluster=staging")

		require.Len(t, seen, 2)
		assert.Equal(t, []string{"staging", "prod"}, []string{seen[0].Context, seen[1].Context}, "--kube-contexts replaces the file's contexts")
		assert.Equal(t, filepath.Join(dir, "file.staging.json"), seen[0].Output, "settings without a flag still come from the file")
		assert.Equal(t, 5, seen[0].Retries)
	})

	t.Run("contexts only from the flag", func(t *testing.T) {
		noContexts := writeFleetConfig(t, "  output: "+filepath.Join(dir, "file.json")+"\n  retries: 1\n")
		seen, _ := runScan(t, "framework", "nsa", "--fleet-config="+noContexts, "--kube-contexts=dr")

		require.Len(t, seen, 1)
		assert.Equal(t, "dr", seen[0].Context)
		assert.Equal(t, 1, seen[0].Retries)
	})
}

// TestFleetConfigIsValidatedLikeFlags pins that bad values from the file are rejected before any scan, as the flags would be.
func TestFleetConfigIsValidatedLikeFlags(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "report.json")
	fleetReport := filepath.Join(dir, "fleet.json")
	tests := map[string]struct {
		spec string
		args []string
		want string
	}{
		"no contexts":       {spec: "  output: " + output + "\n", want: "names no contexts"},
		"no output":         {spec: "  contexts: [prod]\n", want: "--kube-contexts requires --output"},
		"negative retries":  {spec: "  contexts: [prod]\n  output: " + output + "\n  retries: -1\n", want: "--retries -1 is negative"},
		"unknown reference": {spec: "  contexts: [prod]\n  output: " + output + "\n  fleetReport: " + fleetReport + "\n  referenceCluster: dr\n", want: `--reference-cluster "dr" is not one of --kube-contexts`},
		"misspelt field":    {spec: "  context: [prod]\n", want: "field context not found"},
		"not a fleet scan":  {spec: "  contexts: [prod]\n  output: " + output + "\n", args: []string{"image", "nginx"}, want: "--kube-contexts is not yet supported for 'scan image'"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			args := tt.args
			if args == nil {
				args = []string{"framework", "nsa"}
			}
			seen, err := runScan(t, append(args, "--fleet-config="+writeFleetConfig(t, tt.spec))...)

			require.ErrorContains(t, err, tt.want)
			assert.Empty(t, seen, "nothing is scanned when the config is rejected")
		})
	}
}

// TestFleetConfigMissingFile pins that a fleet config that cannot be read stops the scan.
func TestFleetConfigMissingFile(t *testing.T) {
	seen, err := runScan(t, "framework", "nsa", "--fleet-config="+filepath.Join(t.TempDir(), "missing.yaml"))

	require.ErrorContains(t, err, "read fleet config")
	assert.Empty(t, seen)
}
