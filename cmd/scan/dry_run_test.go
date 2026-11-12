package scan

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/kubescape/kubescape/v4/core/pkg/fleet"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type dryRunMockKubescape struct {
	mocks.MockIKubescape
	err error
}

func (m *dryRunMockKubescape) Context() context.Context {
	return context.Background()
}

func (m *dryRunMockKubescape) ScanContext(_ context.Context, _ *cautils.ScanInfo, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	if m.err != nil {
		return nil, m.err
	}
	rh := resultshandling.NewResultsHandler(nil, nil, &fakePrinter{})
	// A dry run finishes after RBAC preflight, so ScanData contains no Report (Report is nil).
	rh.SetData(&cautils.OPASessionObj{})
	return rh, nil
}

func TestRunners_DryRunReturnsCleanlyWithoutPanic(t *testing.T) {
	runners := map[string]fleetRunner{
		"security":  runSecurityScan,
		"framework": runFrameworkScan,
		"control":   runControlScan,
		"workload":  runWorkloadScan,
	}

	for name, run := range runners {
		t.Run(name, func(t *testing.T) {
			ks := &dryRunMockKubescape{}
			scanInfo := &cautils.ScanInfo{
				DryRun:                true,
				ComplianceThreshold:   80,
				FailThresholdSeverity: "low",
			}

			results, err := run(context.Background(), scanInfo, ks, nil)
			require.NoError(t, err)
			require.NotNil(t, results)
			assert.Nil(t, results.GetData().Report, "dry-run results have no Report")
		})
	}
}

func TestRunners_DryRunPropagatesPreflightError(t *testing.T) {
	runners := map[string]fleetRunner{
		"security":  runSecurityScan,
		"framework": runFrameworkScan,
		"control":   runControlScan,
		"workload":  runWorkloadScan,
	}

	preflightErr := errors.New("dry-run: 2 required resource type(s) cannot be listed with the current credentials")

	for name, run := range runners {
		t.Run(name, func(t *testing.T) {
			ks := &dryRunMockKubescape{err: preflightErr}
			scanInfo := &cautils.ScanInfo{
				DryRun: true,
			}

			results, err := run(context.Background(), scanInfo, ks, nil)
			require.Error(t, err)
			assert.ErrorIs(t, err, preflightErr)
			assert.Nil(t, results)
		})
	}
}

func TestFleetScan_DryRun(t *testing.T) {
	ks := &dryRunMockKubescape{}
	scanInfo := cautils.ScanInfo{
		DryRun:       true,
		KubeContexts: []string{"ctx1", "ctx2"},
		Output:       filepath.Join(t.TempDir(), "report.json"),
		AccountID:    "account-1",
	}

	err := fleetScan(scanInfo, ks, nil, runSecurityScan)
	require.Error(t, err)
	assert.ErrorContains(t, err, "--dry-run cannot be combined with fleet scanning")
}

func TestFleetScan_DryRun_CLIInvocationRejection(t *testing.T) {
	ks := &dryRunMockKubescape{}
	root := &cobra.Command{Use: "kubescape", SilenceErrors: true, SilenceUsage: true}
	root.AddCommand(GetScanCommand(ks))
	root.SetArgs([]string{"scan", "--dry-run", "--kube-contexts", "ctx1,ctx2", "-o", filepath.Join(t.TempDir(), "report.json")})

	err := root.Execute()
	require.Error(t, err)
	assert.ErrorContains(t, err, "--dry-run cannot be combined with fleet scanning")
}

func TestNewClusterResult_NilReportFixture(t *testing.T) {
	// Case 1: results is nil
	res1 := newClusterResult("ctx1", nil, errors.New("cluster connection refused"), 100*time.Millisecond)
	assert.Equal(t, fleet.ClusterError, res1.Status)
	assert.Equal(t, "cluster connection refused", res1.Error)

	// Case 2: results has nil OPASessionObj
	rhNilData := resultshandling.NewResultsHandler(nil, nil, &fakePrinter{})
	res2 := newClusterResult("ctx2", rhNilData, nil, 100*time.Millisecond)
	assert.Equal(t, fleet.ClusterError, res2.Status)

	// Case 3: results has non-nil OPASessionObj with nil Report (nil-Report fixture)
	rhNilReport := resultshandling.NewResultsHandler(nil, nil, &fakePrinter{})
	rhNilReport.SetData(&cautils.OPASessionObj{})
	res3 := newClusterResult("ctx3", rhNilReport, nil, 100*time.Millisecond)
	assert.Equal(t, fleet.ClusterError, res3.Status)

	// Case 4: results with valid mock report
	rhValid := resultshandling.NewResultsHandler(nil, nil, &fakePrinter{})
	rhValid.SetData(cautils.NewOPASessionObjMock())
	res4 := newClusterResult("ctx4", rhValid, nil, 100*time.Millisecond)
	assert.Equal(t, fleet.ClusterScanned, res4.Status)
	assert.NotNil(t, res4.Report)
}
