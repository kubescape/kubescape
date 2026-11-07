package scan

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type dryRunMockKubescape struct {
	mocks.MockIKubescape
	err error
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
	require.NoError(t, err)
}


