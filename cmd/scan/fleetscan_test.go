package scan

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/meta"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPerContextOutputPath(t *testing.T) {
	tests := []struct {
		name        string
		output      string
		kubeContext string
		want        string
		wantErr     bool
	}{
		{name: "simple", output: "report.json", kubeContext: "ctx-a", want: "report.ctx-a.json"},
		{name: "no extension", output: "report", kubeContext: "ctx-a", want: "report.ctx-a"},
		{name: "with directory", output: filepath.Join("out", "report.yaml"), kubeContext: "ctx-a", want: filepath.Join("out", "report.ctx-a.yaml")},
		{name: "context contains path separators", output: "report.json", kubeContext: "prod/us-east-1", want: "report.prod_us-east-1.json"},
		{name: "empty context rejected", output: "report.json", kubeContext: "", wantErr: true},
		{name: "whitespace-only context rejected", output: "report.json", kubeContext: "   ", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := perContextOutputPath(tt.output, tt.kubeContext)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// scanContextOnlyRunner is a minimal fleetRunner used by tests that exercise
// fleetScan's own loop/validation behavior in isolation, without pulling in
// runSecurityScan/runFrameworkScan/runControlScan/runWorkloadScan's
// threshold-enforcement logic (covered separately by each command's own
// tests).
func scanContextOnlyRunner(ctx context.Context, scanInfo *cautils.ScanInfo, ks meta.IKubescape, policyIdentifiers []cautils.PolicyIdentifier) error {
	_, err := ks.ScanContext(ctx, scanInfo, policyIdentifiers)
	return err
}

// TestPerContextOutputPaths_RejectsCollidingContexts is a regression test
// for a real review finding on #3438: perContextOutputPath's sanitization
// isn't injective, so two distinct context names - e.g. "prod/us-east-1"
// and "prod_us-east-1" - can derive the same output path and silently
// overwrite each other's report, with fleetScan never noticing since both
// individual scans "succeed." perContextOutputPaths must catch this before
// any scanning starts, not after.
func TestPerContextOutputPaths_RejectsCollidingContexts(t *testing.T) {
	_, err := perContextOutputPaths("report.json", []string{"prod/us-east-1", "prod_us-east-1", "ctx-c"})

	require.Error(t, err)
	assert.ErrorContains(t, err, "prod/us-east-1")
	assert.ErrorContains(t, err, "prod_us-east-1")
	assert.ErrorContains(t, err, "report.prod_us-east-1.json")
}

func TestPerContextOutputPaths_NoCollisions(t *testing.T) {
	paths, err := perContextOutputPaths("report.json", []string{"ctx-a", "ctx-b", "ctx-c"})

	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"ctx-a": "report.ctx-a.json",
		"ctx-b": "report.ctx-b.json",
		"ctx-c": "report.ctx-c.json",
	}, paths)
}

func TestFleetScan_RejectsCollidingContextsBeforeScanningAny(t *testing.T) {
	ks := &fleetTrackingKubescape{}
	scanInfo := cautils.ScanInfo{
		KubeContexts: []string{"prod/us-east-1", "prod_us-east-1"},
		Output:       "report.json",
		ScanType:     cautils.ScanTypeCluster,
	}

	err := fleetScan(scanInfo, ks, nil, scanContextOnlyRunner)

	require.Error(t, err)
	assert.ErrorContains(t, err, "colliding")
	assert.Empty(t, ks.callsOutputs, "no context should be scanned once a collision is detected up front")
}

func TestFleetScan_RequiresClusterScanningContext(t *testing.T) {
	scanInfo := cautils.ScanInfo{
		KubeContexts:  []string{"ctx-a"},
		Output:        "report.json",
		InputPatterns: []string{"."}, // makes GetScanningContext() resolve to a non-cluster context
	}

	err := fleetScan(scanInfo, &mocks.MockIKubescape{}, nil, scanContextOnlyRunner)
	require.ErrorContains(t, err, "live-cluster scan")
}

func TestFleetScan_RequiresOutput(t *testing.T) {
	scanInfo := cautils.ScanInfo{
		KubeContexts: []string{"ctx-a"},
	}

	err := fleetScan(scanInfo, &mocks.MockIKubescape{}, nil, scanContextOnlyRunner)
	require.ErrorContains(t, err, "--output")
}

// fleetTrackingKubescape is a test-local IKubescape recording, per
// ScanContext call, the output path it was given (which encodes the
// context, via perContextOutputPath) - and optionally failing for
// caller-chosen output paths, so tests can assert fleetScan continues past
// a failing context instead of aborting the loop.
type fleetTrackingKubescape struct {
	mocks.MockIKubescape
	callsOutputs []string
	failOutputs  map[string]error
}

func (m *fleetTrackingKubescape) Context() context.Context { return context.Background() }

func (m *fleetTrackingKubescape) ScanContext(_ context.Context, scanInfo *cautils.ScanInfo, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	m.callsOutputs = append(m.callsOutputs, scanInfo.Output)
	if err, ok := m.failOutputs[scanInfo.Output]; ok {
		return nil, err
	}
	results := resultshandling.NewResultsHandler(nil, nil, &fakePrinter{})
	results.SetData(cautils.NewOPASessionObjMock())
	return results, nil
}

func TestFleetScan_ScansEveryContextAndDerivesDistinctOutputPaths(t *testing.T) {
	ks := &fleetTrackingKubescape{}
	scanInfo := cautils.ScanInfo{
		KubeContexts: []string{"ctx-a", "ctx-b", "ctx-c"},
		Output:       "report.json",
		ScanType:     cautils.ScanTypeCluster,
	}

	err := fleetScan(scanInfo, ks, nil, scanContextOnlyRunner)

	require.NoError(t, err)
	assert.Equal(t, []string{"report.ctx-a.json", "report.ctx-b.json", "report.ctx-c.json"}, ks.callsOutputs)
}

func TestFleetScan_ContinuesPastFailingContextAndReportsIt(t *testing.T) {
	ks := &fleetTrackingKubescape{
		failOutputs: map[string]error{
			"report.ctx-b.json": errors.New("cluster unreachable"),
		},
	}
	scanInfo := cautils.ScanInfo{
		KubeContexts: []string{"ctx-a", "ctx-b", "ctx-c"},
		Output:       "report.json",
		ScanType:     cautils.ScanTypeCluster,
	}

	err := fleetScan(scanInfo, ks, nil, scanContextOnlyRunner)

	require.Error(t, err)
	assert.ErrorContains(t, err, "1 of 3 context(s) failed")
	assert.ErrorContains(t, err, "ctx-b")
	assert.ErrorContains(t, err, "cluster unreachable")
	// ctx-a and ctx-c must still have been attempted despite ctx-b failing.
	assert.Equal(t, []string{"report.ctx-a.json", "report.ctx-b.json", "report.ctx-c.json"}, ks.callsOutputs)
}

func TestFleetScan_EachContextGetsAFreshScanID(t *testing.T) {
	var scanIDs []string
	ks := &fleetIDTrackingKubescape{onScan: func(si *cautils.ScanInfo) {
		scanIDs = append(scanIDs, si.ScanID)
	}}
	scanInfo := cautils.ScanInfo{
		KubeContexts: []string{"ctx-a", "ctx-b"},
		Output:       "report.json",
		ScanType:     cautils.ScanTypeCluster,
	}
	scanInfo.ScanID = "should-not-be-reused"

	require.NoError(t, fleetScan(scanInfo, ks, nil, scanContextOnlyRunner))

	require.Len(t, scanIDs, 2)
	assert.NotEqual(t, "should-not-be-reused", scanIDs[0])
	assert.NotEqual(t, "should-not-be-reused", scanIDs[1])
	assert.NotEqual(t, scanIDs[0], scanIDs[1], "each context must get its own ScanID, not share one across the fleet")
}

type fleetIDTrackingKubescape struct {
	mocks.MockIKubescape
	onScan func(*cautils.ScanInfo)
}

func (m *fleetIDTrackingKubescape) Context() context.Context { return context.Background() }

func (m *fleetIDTrackingKubescape) ScanContext(_ context.Context, scanInfo *cautils.ScanInfo, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	// Mirrors what the real Scan/ScanContext does via scanInfo.Init: assign a
	// ScanID if one isn't already set. CloneForContext is what's under test
	// here - it must have cleared ScanID before this call ever sees it.
	if scanInfo.ScanID == "" {
		scanInfo.ScanID = "generated-" + scanInfo.Output
	}
	m.onScan(scanInfo)
	results := resultshandling.NewResultsHandler(nil, nil, &fakePrinter{})
	results.SetData(cautils.NewOPASessionObjMock())
	return results, nil
}

// TestGetFrameworkCmd_KubeContextsDispatchesToFleetScan, TestGetControlCmd_*,
// and TestGetWorkloadCmd_* below exercise each command's real RunE end to
// end with --kube-contexts set, proving the dispatch added alongside
// runFrameworkScan/runControlScan/runWorkloadScan actually reaches
// fleetScan and scans every requested context - not just that fleetScan
// itself works in isolation (covered above) or that the single-context path
// still works (covered by each command's own pre-existing tests).

func TestGetFrameworkCmd_KubeContextsDispatchesToFleetScan(t *testing.T) {
	ks := &fleetTrackingKubescape{}
	scanInfo := cautils.ScanInfo{
		KubeContexts: []string{"ctx-a", "ctx-b"},
		Output:       "report.json",
	}

	cmd := getFrameworkCmd(ks, &scanInfo)
	err := cmd.RunE(&cobra.Command{}, []string{"nsa"})

	require.NoError(t, err)
	assert.Equal(t, []string{"report.ctx-a.json", "report.ctx-b.json"}, ks.callsOutputs)
}

func TestGetControlCmd_KubeContextsDispatchesToFleetScan(t *testing.T) {
	ks := &fleetTrackingKubescape{}
	scanInfo := cautils.ScanInfo{
		KubeContexts: []string{"ctx-a", "ctx-b"},
		Output:       "report.json",
	}

	cmd := getControlCmd(ks, &scanInfo)
	err := cmd.RunE(&cobra.Command{}, []string{"C-0058"})

	require.NoError(t, err)
	assert.Equal(t, []string{"report.ctx-a.json", "report.ctx-b.json"}, ks.callsOutputs)
}

func TestGetWorkloadCmd_KubeContextsDispatchesToFleetScan(t *testing.T) {
	ks := &fleetTrackingKubescape{}
	scanInfo := cautils.ScanInfo{
		KubeContexts: []string{"ctx-a", "ctx-b"},
		Output:       "report.json",
	}

	cmd := getWorkloadCmd(ks, &scanInfo)
	err := cmd.RunE(&cobra.Command{}, []string{"Deployment/nginx"})

	require.NoError(t, err)
	assert.Equal(t, []string{"report.ctx-a.json", "report.ctx-b.json"}, ks.callsOutputs)
}
