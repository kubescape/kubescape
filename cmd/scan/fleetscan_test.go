package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/core"
	"github.com/kubescape/kubescape/v4/core/meta"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/kubescape/kubescape/v4/core/pkg/fleet"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
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
func scanContextOnlyRunner(ctx context.Context, scanInfo *cautils.ScanInfo, ks meta.IKubescape, policyIdentifiers []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	return ks.ScanContext(ctx, scanInfo, policyIdentifiers)
}

// TestPerContextOutputPaths_RejectsCollidingContexts is a regression test
// for a realDir review finding on #3438: perContextOutputPath's sanitization
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

// TestValidateKubeContextsSupported_FrameworkControlWorkloadAllowed guards
// against a realDir regression this PR's own dispatch tests can't catch: they
// all call cmd.RunE directly, bypassing scanCmd's PersistentPreRunE, which
// is where validateKubeContextsSupported actually runs against a realDir CLI
// invocation. Before framework/control/workload were added to its switch,
// validateKubeContextsSupported's default case rejected --kube-contexts for
// exactly the three subcommands this PR exists to support, breaking the
// feature end to end despite every dispatch test passing.
func TestValidateKubeContextsSupported_FrameworkControlWorkloadAllowed(t *testing.T) {
	for _, name := range []string{"framework", "control", "workload"} {
		cmd := &cobra.Command{Use: name}
		scanInfo := &cautils.ScanInfo{KubeContexts: []string{"ctx-a"}}
		if err := validateKubeContextsSupported(cmd, scanInfo); err != nil {
			t.Errorf("cmd.Name()=%q: validateKubeContextsSupported returned error, want nil: %v", name, err)
		}
	}
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
	// Mirrors what the realDir Scan/ScanContext does via scanInfo.Init: assign a
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
// and TestGetWorkloadCmd_* below exercise each command's realDir RunE end to
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

// fleetReportFromFile decodes the fleet report fleetScan wrote to path.
func fleetReportFromFile(t *testing.T, path string) fleet.FleetReport {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	require.NoError(t, err, "fleet report was not written")
	var report fleet.FleetReport
	require.NoError(t, json.Unmarshal(raw, &report), "fleet report is not valid JSON")
	return report
}

// resultsWithControl builds a ResultsHandler whose session carries C-0016
// with the given status, so a test can see the cell it produces in the matrix.
// The session also carries a raw resource, so a test can check it is not
// copied into the fleet report.
func resultsWithControl(status apis.ScanningStatus, complianceScore float32) *resultshandling.ResultsHandler {
	const controlID = "C-0016"
	session := cautils.NewOPASessionObjMock()
	session.Report.SummaryDetails.ComplianceScore = complianceScore
	session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{
		controlID: {
			ControlID:  controlID,
			Name:       "Allow privilege escalation",
			StatusInfo: apis.StatusInfo{InnerStatus: status},
			Status:     status,
		},
	}
	session.ScanCoverage = cautils.ScanCoverage{CoverageScore: 100, EvaluatedControls: 1, TotalControls: 1}
	session.AllResources["apps/v1/default/Deployment/web"] = nil

	results := resultshandling.NewResultsHandler(nil, nil, &fakePrinter{})
	results.SetData(session)
	return results
}

// fleetOutcomeKubescape lets a test choose, per context, what ScanContext
// returns: results, an error, or both.
type fleetOutcomeKubescape struct {
	mocks.MockIKubescape
	outcomes map[string]func() (*resultshandling.ResultsHandler, error)
}

func (m *fleetOutcomeKubescape) Context() context.Context { return context.Background() }

func (m *fleetOutcomeKubescape) ScanContext(_ context.Context, scanInfo *cautils.ScanInfo, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	if outcome, ok := m.outcomes[scanInfo.GetClusterContextName()]; ok {
		return outcome()
	}
	return resultsWithControl(apis.StatusPassed, 100), nil
}

func TestNewClusterResult_ClassifiesByResultsFirstThenError(t *testing.T) {
	tests := []struct {
		name       string
		results    *resultshandling.ResultsHandler
		err        error
		wantStatus fleet.ClusterScanStatus
		wantReport bool
	}{
		{
			name:       "scan completed cleanly",
			results:    resultsWithControl(apis.StatusPassed, 100),
			wantStatus: fleet.ClusterScanned,
			wantReport: true,
		},
		{
			// The case the classification exists for. Every runner returns its
			// results together with an error on a threshold breach, and that
			// cluster was measured. Treating the error as a failed scan would
			// drop the one cluster an operator most needs to see.
			name:       "scan completed but breached its compliance threshold",
			results:    resultsWithControl(apis.StatusFailed, 40),
			err:        errors.New("scan compliance-score is below permitted threshold: 40.00 (compliance-threshold: 80.00)"),
			wantStatus: fleet.ClusterScanned,
			wantReport: true,
		},
		{
			name:       "api server never reached",
			err:        fmt.Errorf("prod: %w", core.ErrClusterConnection),
			wantStatus: fleet.ClusterUnreachable,
		},
		{
			name:       "run interrupted",
			err:        context.Canceled,
			wantStatus: fleet.ClusterCancelled,
		},
		{
			name:       "per-cluster scan timeout expired",
			err:        fmt.Errorf("scan: %w", context.DeadlineExceeded),
			wantStatus: fleet.ClusterCancelled,
		},
		{
			name:       "scan started and failed inside",
			err:        errors.New("policy download failed"),
			wantStatus: fleet.ClusterError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newClusterResult("prod", tt.results, tt.err, 90*time.Second)

			assert.Equal(t, "prod", got.ClusterID)
			assert.Equal(t, "prod", got.Context)
			assert.Equal(t, "1m30s", got.Duration)
			assert.Equal(t, tt.wantStatus, got.Status)
			assert.Equal(t, tt.wantReport, got.Scanned(), "Scanned() must agree with the status")

			if tt.wantReport {
				require.NotNil(t, got.ComplianceScore)
				require.NotNil(t, got.Coverage)
				assert.Empty(t, got.Error, "a scanned cluster's gate failure belongs to the exit code, not to the cluster row")
				return
			}
			assert.Nil(t, got.Report)
			assert.Nil(t, got.ComplianceScore, "an unscanned cluster must not carry a score")
			assert.Nil(t, got.Coverage, "an unscanned cluster must not carry coverage")
			assert.Equal(t, tt.err.Error(), got.Error, "the error is kept verbatim so the reader can tell an expired credential from an unroutable API server")
		})
	}
}

func TestNewClusterResult_DropsRawResourcesButKeepsResults(t *testing.T) {
	results := resultsWithControl(apis.StatusFailed, 0)
	require.NotEmpty(t, results.GetData().AllResources, "fixture must start with a raw resource for this test to mean anything")
	require.False(t, results.GetData().OmitRawResources, "the drop must not depend on --omit-raw-resources")

	got := newClusterResult("prod", results, nil, time.Second)

	require.NotNil(t, got.Report)
	assert.Nil(t, got.Report.Resources, "raw manifests already live in the per-context file; holding them for every cluster until the run ends is the cost the fleet report must not pay")
	assert.NotNil(t, got.Report.Results, "per-resource results are what later aggregation reads and must be kept")
	assert.Contains(t, got.Report.SummaryDetails.Controls, "C-0016")
}

func TestFleetScan_WritesFleetReportAcrossEveryOutcome(t *testing.T) {
	dir := t.TempDir()
	fleetReport := filepath.Join(dir, "fleet.json")
	ks := &fleetOutcomeKubescape{outcomes: map[string]func() (*resultshandling.ResultsHandler, error){
		"prod": func() (*resultshandling.ResultsHandler, error) {
			return resultsWithControl(apis.StatusFailed, 40), errors.New("scan compliance-score is below permitted threshold")
		},
		"staging": func() (*resultshandling.ResultsHandler, error) {
			return resultsWithControl(apis.StatusPassed, 100), nil
		},
		"dr": func() (*resultshandling.ResultsHandler, error) {
			return nil, fmt.Errorf("dr: %w", core.ErrClusterConnection)
		},
	}}
	scanInfo := cautils.ScanInfo{
		KubeContexts: []string{"prod", "staging", "dr"},
		Output:       filepath.Join(dir, "report.json"),
		FleetReport:  fleetReport,
		ScanType:     cautils.ScanTypeCluster,
	}

	err := fleetScan(scanInfo, ks, nil, scanContextOnlyRunner)

	// prod breached its gate and dr was unreachable, so the exit code still
	// reports two failures. Writing the fleet report changes nothing there.
	require.ErrorContains(t, err, "2 of 3 context(s) failed")

	report := fleetReportFromFile(t, fleetReport)
	assert.Equal(t, []string{"prod", "staging", "dr"}, report.Metadata.Contexts)
	assert.False(t, report.Metadata.GeneratedAt.IsZero())

	require.Len(t, report.Clusters, 3, "every requested context gets a row, scanned or not")
	byID := map[string]fleet.ClusterResult{}
	for _, cluster := range report.Clusters {
		byID[cluster.ClusterID] = cluster
	}
	assert.Equal(t, fleet.ClusterScanned, byID["prod"].Status, "a threshold breach is still a scanned cluster")
	prod := byID["prod"]
	assert.True(t, prod.Scanned())
	assert.Equal(t, fleet.ClusterScanned, byID["staging"].Status)
	assert.Equal(t, fleet.ClusterUnreachable, byID["dr"].Status)
	assert.Contains(t, byID["dr"].Error, "failed connecting to Kubernetes cluster")
	assert.Nil(t, byID["dr"].ComplianceScore)

	require.Len(t, report.ControlMatrix.Controls, 1)
	row := report.ControlMatrix.Controls[0]
	assert.Equal(t, "C-0016", row.ControlID)
	assert.Equal(t, fleet.CellFailed, row.ByCluster["prod"].Status)
	assert.Equal(t, fleet.CellPassed, row.ByCluster["staging"].Status)
	assert.NotContains(t, row.ByCluster, "dr", "an unreachable cluster has no opinion about any control")
}

func TestFleetScan_WithoutFleetReportWritesNothingExtra(t *testing.T) {
	dir := t.TempDir()
	ks := &fleetTrackingKubescape{}
	scanInfo := cautils.ScanInfo{
		KubeContexts: []string{"ctx-a", "ctx-b"},
		Output:       filepath.Join(dir, "report.json"),
		ScanType:     cautils.ScanTypeCluster,
	}

	require.NoError(t, fleetScan(scanInfo, ks, nil, scanContextOnlyRunner))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries, "the fake printer writes nothing, so anything here would be the fleet report appearing unasked")
}

// resultsNeverReadKubescape returns a ResultsHandler with no scan data behind
// it. Reading it (GetResults, GetComplianceScore) would panic, so a run that
// passes without a fleet report proves fleetScan never touched the results.
type resultsNeverReadKubescape struct {
	mocks.MockIKubescape
}

func (m *resultsNeverReadKubescape) Context() context.Context { return context.Background() }

func (m *resultsNeverReadKubescape) ScanContext(_ context.Context, _ *cautils.ScanInfo, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	return resultshandling.NewResultsHandler(nil, nil, &fakePrinter{}), nil
}

func TestFleetScan_WithoutFleetReportDoesNotRetainOrReadResults(t *testing.T) {
	scanInfo := cautils.ScanInfo{
		KubeContexts: []string{"ctx-a", "ctx-b"},
		Output:       filepath.Join(t.TempDir(), "report.json"),
		ScanType:     cautils.ScanTypeCluster,
	}

	// A plain --kube-contexts run must not pay for aggregation it did not ask
	// for. If fleetScan read the results here it would panic on the nil data.
	require.NoError(t, fleetScan(scanInfo, &resultsNeverReadKubescape{}, nil, scanContextOnlyRunner))
}

func TestFleetScan_UnwritableFleetReportIsAFailure(t *testing.T) {
	dir := t.TempDir()
	ks := &fleetTrackingKubescape{}
	scanInfo := cautils.ScanInfo{
		KubeContexts: []string{"ctx-a"},
		Output:       filepath.Join(dir, "report.json"),
		FleetReport:  filepath.Join(dir, "report.json", "fleet.json"), // parent is a file path, so it cannot be a directory
		ScanType:     cautils.ScanTypeCluster,
	}

	// Make the parent exist as a file so MkdirAll fails on it.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "report.json"), []byte("{}"), 0o600))

	err := fleetScan(scanInfo, ks, nil, scanContextOnlyRunner)

	require.ErrorContains(t, err, "fleet report was not written", "the run scanned every context but could not save what it was asked for")
	assert.NotContains(t, err.Error(), "context(s) failed", "the only context succeeded, so it must not be counted as a failure")
	assert.Equal(t, []string{filepath.Join(dir, "report.ctx-a.json")}, ks.callsOutputs, "the context was still scanned")
}

func TestFleetScan_ReportsContextFailuresAndFleetReportFailureSeparately(t *testing.T) {
	dir := t.TempDir()
	ks := &fleetOutcomeKubescape{outcomes: map[string]func() (*resultshandling.ResultsHandler, error){
		"dr": func() (*resultshandling.ResultsHandler, error) { return nil, errors.New("no route to host") },
	}}
	scanInfo := cautils.ScanInfo{
		KubeContexts: []string{"prod", "dr"},
		Output:       filepath.Join(dir, "report.json"),
		FleetReport:  filepath.Join(dir, "report.json", "fleet.json"),
		ScanType:     cautils.ScanTypeCluster,
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "report.json"), []byte("{}"), 0o600))

	err := fleetScan(scanInfo, ks, nil, scanContextOnlyRunner)

	require.ErrorContains(t, err, "1 of 2 context(s) failed", "only dr failed; the fleet report is not a context")
	require.ErrorContains(t, err, "dr: no route to host")
	require.ErrorContains(t, err, "fleet report:")
}

func TestValidateFleetReportPath_RejectsCollisionWithPerContextReport(t *testing.T) {
	paths, err := perContextOutputPaths("out/report.json", []string{"prod", "staging"})
	require.NoError(t, err)

	err = validateFleetReportPath("out/report.prod.json", paths)
	require.ErrorContains(t, err, "prod")
	require.ErrorContains(t, err, "overwrite")

	assert.NoError(t, validateFleetReportPath("out/fleet.json", paths))
	assert.NoError(t, validateFleetReportPath("", paths), "no fleet report requested, nothing to collide with")

	// The same file spelled two ways is still the same file.
	abs, err := filepath.Abs("out/report.staging.json")
	require.NoError(t, err)
	err = validateFleetReportPath(abs, paths)
	require.ErrorContains(t, err, "staging", "an absolute --fleet-report must be caught against a relative --output")
}

func TestFleetScan_RejectsFleetReportCollidingWithPerContextReportBeforeScanning(t *testing.T) {
	ks := &fleetTrackingKubescape{}
	scanInfo := cautils.ScanInfo{
		KubeContexts: []string{"prod"},
		Output:       "report.json",
		FleetReport:  "report.prod.json",
		ScanType:     cautils.ScanTypeCluster,
	}

	err := fleetScan(scanInfo, ks, nil, scanContextOnlyRunner)

	require.ErrorContains(t, err, "overwrite")
	assert.Empty(t, ks.callsOutputs, "a collision is a configuration error and must be reported before any cluster is touched")
}

// fleetFileWritingKubescape writes a per-context report file the way a realDir
// printer would, so tests can check what happens once those files exist.
type fleetFileWritingKubescape struct {
	mocks.MockIKubescape
	callsOutputs []string
}

func (m *fleetFileWritingKubescape) Context() context.Context { return context.Background() }

func (m *fleetFileWritingKubescape) ScanContext(_ context.Context, scanInfo *cautils.ScanInfo, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	m.callsOutputs = append(m.callsOutputs, scanInfo.Output)
	if err := os.WriteFile(scanInfo.Output, []byte(`{"clusterName":"`+scanInfo.GetClusterContextName()+`"}`), 0o600); err != nil {
		return nil, err
	}
	return resultsWithControl(apis.StatusPassed, 100), nil
}

func TestFleetScan_RejectsFleetReportSymlinkedToExistingPerContextReport(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs elevated rights on windows")
	}
	dir := t.TempDir()
	perContext := filepath.Join(dir, "report.prod.json")
	require.NoError(t, os.WriteFile(perContext, []byte(`{"from":"previous run"}`), 0o600))
	link := filepath.Join(dir, "fleet.json")
	require.NoError(t, os.Symlink(perContext, link))

	ks := &fleetFileWritingKubescape{}
	scanInfo := cautils.ScanInfo{
		KubeContexts: []string{"prod"},
		Output:       filepath.Join(dir, "report.json"),
		FleetReport:  link,
		ScanType:     cautils.ScanTypeCluster,
	}

	err := fleetScan(scanInfo, ks, nil, scanContextOnlyRunner)

	require.ErrorContains(t, err, "resolves to the per-context report")
	assert.Empty(t, ks.callsOutputs, "a report from a previous run already resolves, so this is caught before any cluster is scanned")
	got, readErr := os.ReadFile(filepath.Clean(perContext))
	require.NoError(t, readErr)
	assert.JSONEq(t, `{"from":"previous run"}`, string(got), "the per-context report must be untouched")
}

func TestFleetScan_RejectsDanglingSymlinkBeforeScanning(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs elevated rights on windows")
	}
	dir := t.TempDir()
	perContext := filepath.Join(dir, "report.prod.json")
	link := filepath.Join(dir, "fleet.json")
	// Nothing at the target yet. The link is read lexically, so it is still
	// caught before any cluster is touched.
	require.NoError(t, os.Symlink(perContext, link))

	ks := &fleetFileWritingKubescape{}
	scanInfo := cautils.ScanInfo{
		KubeContexts: []string{"prod"},
		Output:       filepath.Join(dir, "report.json"),
		FleetReport:  link,
		ScanType:     cautils.ScanTypeCluster,
	}

	err := fleetScan(scanInfo, ks, nil, scanContextOnlyRunner)

	require.ErrorContains(t, err, "resolves to the per-context report")
	assert.Empty(t, ks.callsOutputs, "a dangling link to a per-context path is a configuration error, caught before scanning")
	assert.NoFileExists(t, perContext, "nothing may be created at the per-context path")
}

func TestFleetScan_DanglingSymlinkWithFailedContextWritesNothingAtPerContextPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs elevated rights on windows")
	}
	dir := t.TempDir()
	perContext := filepath.Join(dir, "report.prod.json")
	link := filepath.Join(dir, "fleet.json")
	require.NoError(t, os.Symlink(perContext, link))

	// prod fails, so its report is never written and the link stays dangling
	// all the way to the fleet report write. Following it there would leave
	// fleet JSON sitting at prod's report path, looking like prod's report.
	ks := &fleetOutcomeKubescape{outcomes: map[string]func() (*resultshandling.ResultsHandler, error){
		"prod": func() (*resultshandling.ResultsHandler, error) { return nil, errors.New("no route to host") },
	}}
	scanInfo := cautils.ScanInfo{
		KubeContexts: []string{"prod"},
		Output:       filepath.Join(dir, "report.json"),
		FleetReport:  link,
		ScanType:     cautils.ScanTypeCluster,
	}

	err := fleetScan(scanInfo, ks, nil, scanContextOnlyRunner)

	require.ErrorContains(t, err, "resolves to the per-context report")
	assert.NoFileExists(t, perContext, "fleet JSON must not be written through the link to the per-context path")
}

func TestFleetScan_RejectsSymlinkedParentDirectoryWithFailedContext(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs elevated rights on windows")
	}
	dir := t.TempDir()
	realDir := filepath.Join(dir, "realDir")
	require.NoError(t, os.Mkdir(realDir, 0o750))
	alias := filepath.Join(dir, "alias")
	require.NoError(t, os.Symlink(realDir, alias))

	// prod fails, so realDir/report.prod.json is never written. The fleet report
	// path names the same file through the aliased directory; nothing on the
	// final component is a link, so only a parent-aware comparison sees it.
	ks := &fleetOutcomeKubescape{outcomes: map[string]func() (*resultshandling.ResultsHandler, error){
		"prod": func() (*resultshandling.ResultsHandler, error) { return nil, errors.New("no route to host") },
	}}
	scanInfo := cautils.ScanInfo{
		KubeContexts: []string{"prod"},
		Output:       filepath.Join(realDir, "report.json"),
		FleetReport:  filepath.Join(alias, "report.prod.json"),
		ScanType:     cautils.ScanTypeCluster,
	}

	err := fleetScan(scanInfo, ks, nil, scanContextOnlyRunner)

	require.ErrorContains(t, err, "resolves to the per-context report")
	assert.NoFileExists(t, filepath.Join(realDir, "report.prod.json"), "fleet JSON must not land at the per-context path through the aliased directory")
}

func TestFleetScan_RejectsSymlinkedOutputDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs elevated rights on windows")
	}
	dir := t.TempDir()
	realDir := filepath.Join(dir, "realDir")
	require.NoError(t, os.Mkdir(realDir, 0o750))
	alias := filepath.Join(dir, "alias")
	require.NoError(t, os.Symlink(realDir, alias))

	// The link is on the --output side this time and the fleet report path is
	// plain. The comparison has to be symmetric.
	ks := &fleetTrackingKubescape{}
	scanInfo := cautils.ScanInfo{
		KubeContexts: []string{"prod"},
		Output:       filepath.Join(alias, "report.json"),
		FleetReport:  filepath.Join(realDir, "report.prod.json"),
		ScanType:     cautils.ScanTypeCluster,
	}

	err := fleetScan(scanInfo, ks, nil, scanContextOnlyRunner)

	require.ErrorContains(t, err, "resolves to the per-context report")
	assert.Empty(t, ks.callsOutputs, "caught before scanning")
}

func TestCanonicalPath_NotYetCreatedDirectoryBeneathSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs elevated rights on windows")
	}
	dir := t.TempDir()
	realDir := filepath.Join(dir, "realDir")
	require.NoError(t, os.Mkdir(realDir, 0o750))
	alias := filepath.Join(dir, "alias")
	require.NoError(t, os.Symlink(realDir, alias))

	viaAlias, err := canonicalPath(filepath.Join(alias, "new", "deeper", "fleet.json"))
	require.NoError(t, err)
	viaReal, err := canonicalPath(filepath.Join(realDir, "new", "deeper", "fleet.json"))
	require.NoError(t, err)
	assert.Equal(t, viaReal, viaAlias, "directories that do not exist yet must still resolve through the aliased ancestor")
}

func TestLinkChain_FollowsRelativeAndDanglingLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs elevated rights on windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "report.prod.json") // never created
	hop := filepath.Join(dir, "hop")
	require.NoError(t, os.Symlink("report.prod.json", hop)) // relative
	link := filepath.Join(dir, "fleet.json")
	require.NoError(t, os.Symlink(hop, link))

	chain, err := linkChain(link)
	require.NoError(t, err)
	assert.Equal(t, []string{link, hop, target}, chain)

	plain := filepath.Join(dir, "plain.json")
	chain, err = linkChain(plain)
	require.NoError(t, err)
	assert.Equal(t, []string{plain}, chain, "a non-link is a chain of one, existing or not")
}

func TestLinkChain_RejectsCycles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs elevated rights on windows")
	}
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	require.NoError(t, os.Symlink(b, a))
	require.NoError(t, os.Symlink(a, b))

	_, err := linkChain(a)
	require.ErrorContains(t, err, "symbolic links")
}

func TestValidateKubeContextsSupported_FleetReportRequiresKubeContexts(t *testing.T) {
	cmd := &cobra.Command{Use: "scan"}

	err := validateKubeContextsSupported(cmd, &cautils.ScanInfo{FleetReport: "fleet.json"})
	require.ErrorContains(t, err, "--fleet-report requires --kube-contexts")

	assert.NoError(t, validateKubeContextsSupported(cmd, &cautils.ScanInfo{}), "neither flag set is the ordinary single-cluster scan")
}
