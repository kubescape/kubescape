package scan

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/cmd/shared"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failedGate is an attempt that scanned the cluster but breached the compliance threshold.
func failedGate() (*resultshandling.ResultsHandler, error) {
	return resultsWithControl(apis.StatusFailed, 40), gateFailure(errors.New("scan compliance-score is below permitted threshold: 40.00 (compliance-threshold: 80.00)"))
}

// reportNotWritten is an attempt that scanned the cluster but could not write its report.
func reportNotWritten() (*resultshandling.ResultsHandler, error) {
	return resultsWithControl(apis.StatusPassed, 100), errors.New("output printer *printer.JsonPrinter: write failed")
}

// exitScanInfo is a fleet scan of prod and staging with no retries and a fleet report.
func exitScanInfo(t *testing.T) cautils.ScanInfo {
	t.Helper()
	scanInfo := retryScanInfo(t, 0, true)
	scanInfo.KubeContexts = []string{"prod", "staging"}
	return scanInfo
}

// TestFleetScan_ExitCode pins the exit code a fleet run ends with: 1 when every cluster was scanned and only gates failed, 2 when the run is incomplete.
func TestFleetScan_ExitCode(t *testing.T) {
	tests := map[string]struct {
		prod, staging attemptOutcome
		want          int
	}{
		"every cluster passed":                                 {prod: scannedCleanly, staging: scannedCleanly, want: 0},
		"a cluster failed a gate":                              {prod: failedGate, staging: scannedCleanly, want: 1},
		"every cluster failed a gate":                          {prod: failedGate, staging: failedGate, want: 1},
		"a cluster could not be reached":                       {prod: refused, staging: scannedCleanly, want: 2},
		"a gate failed and a cluster could not be reached":     {prod: failedGate, staging: refused, want: 2},
		"a cluster was scanned but its report was not written": {prod: reportNotWritten, staging: scannedCleanly, want: 2},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			runner := newRetryRunner(map[string][]attemptOutcome{"prod": {tt.prod}, "staging": {tt.staging}})

			err := fleetScan(exitScanInfo(t), &fleetTrackingKubescape{}, nil, runner.run)

			assert.Equal(t, tt.want, shared.ExitCode(err))
			if tt.want != 0 {
				assert.ErrorContains(t, err, "context(s) failed", "the message is the same whatever the code")
			}
		})
	}
}

// TestFleetScan_ExitCodeWithoutAFleetReport pins that the code does not depend on --fleet-report.
func TestFleetScan_ExitCodeWithoutAFleetReport(t *testing.T) {
	scanInfo := exitScanInfo(t)
	scanInfo.FleetReport = ""
	runner := newRetryRunner(map[string][]attemptOutcome{"prod": {failedGate}, "staging": {scannedCleanly}})

	assert.Equal(t, 1, shared.ExitCode(fleetScan(scanInfo, &fleetTrackingKubescape{}, nil, runner.run)))
}

// TestFleetScan_ExitCodeWhenTheFleetReportIsNotWritten pins that a missing fleet report makes the run incomplete.
func TestFleetScan_ExitCodeWhenTheFleetReportIsNotWritten(t *testing.T) {
	scanInfo := exitScanInfo(t)
	notADir := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(notADir, nil, 0o600))
	scanInfo.FleetReport = filepath.Join(notADir, "fleet.json")
	runner := newRetryRunner(map[string][]attemptOutcome{"prod": {scannedCleanly}, "staging": {scannedCleanly}})

	err := fleetScan(scanInfo, &fleetTrackingKubescape{}, nil, runner.run)

	require.ErrorContains(t, err, "fleet report was not written")
	assert.Equal(t, 2, shared.ExitCode(err))
}

// TestFleetScan_InvalidInvocationKeepsExitCodeOne pins that a fleet run rejected before it starts exits like any other bad invocation.
func TestFleetScan_InvalidInvocationKeepsExitCodeOne(t *testing.T) {
	scanInfo := exitScanInfo(t)
	scanInfo.Output = ""

	err := fleetScan(scanInfo, &fleetTrackingKubescape{}, nil, newRetryRunner(nil).run)

	require.ErrorContains(t, err, "--kube-contexts requires --output")
	assert.Equal(t, 1, shared.ExitCode(err))
}
