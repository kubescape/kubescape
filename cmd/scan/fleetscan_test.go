package scan

import (
	"bytes"
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

func TestWriteFleetReport_ReplacesExistingReportAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.json")
	require.NoError(t, os.WriteFile(path, []byte("{\"generation\":\"old\"}"), 0o600))

	report := &fleet.FleetReport{
		Metadata: fleet.FleetMetadata{
			GeneratedAt: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
			Contexts:    []string{"prod"},
		},
		Clusters: []fleet.ClusterResult{{ClusterID: "prod", Context: "prod", Status: fleet.ClusterScanned}},
	}
	require.NoError(t, writeFleetReport(path, report))

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.True(t, json.Valid(raw))
	assert.True(t, bytes.HasSuffix(raw, []byte("\n")))
	got := fleetReportFromFile(t, path)
	assert.Equal(t, []string{"prod"}, got.Metadata.Contexts)
	require.Len(t, got.Clusters, 1)
	assert.Equal(t, "prod", got.Clusters[0].ClusterID)
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "replacing a report must preserve its existing mode")
	}
}

func TestWriteFleetReport_DoesNotFollowExistingSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not generally available to unprivileged Windows tests")
	}

	dir := t.TempDir()
	victim := filepath.Join(dir, "per-context.json")
	path := filepath.Join(dir, "fleet.json")
	require.NoError(t, os.WriteFile(victim, []byte("per-context result"), 0o600))
	require.NoError(t, os.Symlink(victim, path))

	report := &fleet.FleetReport{Metadata: fleet.FleetMetadata{Contexts: []string{"prod"}}}
	require.NoError(t, writeFleetReport(path, report))

	victimData, err := os.ReadFile(victim)
	require.NoError(t, err)
	assert.Equal(t, "per-context result", string(victimData))
	reportData, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.True(t, json.Valid(reportData))
	info, err := os.Lstat(path)
	require.NoError(t, err)
	assert.Zero(t, info.Mode()&os.ModeSymlink)
}

func TestWriteFleetReport_PreservesExistingDestinationWhenCommitFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory replacement errors differ on Windows")
	}

	path := filepath.Join(t.TempDir(), "fleet.json")
	require.NoError(t, os.Mkdir(path, 0o750))
	marker := filepath.Join(path, "previous-report")
	require.NoError(t, os.WriteFile(marker, []byte("keep"), 0o600))

	err := writeFleetReport(path, &fleet.FleetReport{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "write fleet report")
	got, readErr := os.ReadFile(marker)
	require.NoError(t, readErr)
	assert.Equal(t, "keep", string(got))
}

func TestWriteFleetReport_CreatesNestedDestinationPrivately(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reports", "fleet", "result.json")
	report := &fleet.FleetReport{Metadata: fleet.FleetMetadata{Contexts: []string{"prod", "dr"}}}

	require.NoError(t, writeFleetReport(path, report))

	got := fleetReportFromFile(t, path)
	assert.Equal(t, []string{"prod", "dr"}, got.Metadata.Contexts)
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())
	}
}

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
	_, err := perContextOutputPaths("report.json", []string{"prod/us-east-1", "prod_us-east-1", "ctx-c"}, nil)

	require.Error(t, err)
	assert.ErrorContains(t, err, "prod/us-east-1")
	assert.ErrorContains(t, err, "prod_us-east-1")
	assert.ErrorContains(t, err, "report.prod_us-east-1.json")
}

func TestPerContextOutputPaths_NoCollisions(t *testing.T) {
	paths, err := perContextOutputPaths("report.json", []string{"ctx-a", "ctx-b", "ctx-c"}, nil)

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
	paths, err := perContextOutputPaths("out/report.json", []string{"prod", "staging"}, nil)
	require.NoError(t, err)

	err = validateFleetReportPath("out/report.prod.json", paths, nil)
	require.ErrorContains(t, err, "prod")
	require.ErrorContains(t, err, "overwrite")

	assert.NoError(t, validateFleetReportPath("out/fleet.json", paths, nil))
	assert.NoError(t, validateFleetReportPath("", paths, nil), "no fleet report requested, nothing to collide with")

	// The same file spelled two ways is still the same file.
	abs, err := filepath.Abs("out/report.staging.json")
	require.NoError(t, err)
	err = validateFleetReportPath(abs, paths, nil)
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

func TestPrinterDestinations_ResolvesTheExtensionEachFormatAppends(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		formats []string
		want    []string
	}{
		{
			// The case the collision check was blind to: --output report
			// derives report.prod, but the JSON printer writes report.prod.json.
			name:    "extensionless output gains the format extension",
			path:    "report.prod",
			formats: []string{"json"},
			want:    []string{"report.prod.json"},
		},
		{
			name:    "an extension already present is left alone",
			path:    "report.prod.json",
			formats: []string{"json"},
			want:    []string{"report.prod.json"},
		},
		{
			name:    "each format contributes its own destination",
			path:    "report.prod",
			formats: []string{"json", "pdf", "sarif"},
			want:    []string{"report.prod.json", "report.prod.pdf", "report.prod.sarif"},
		},
		{
			name:    "formats sharing an extension collapse to one destination",
			path:    "report.prod",
			formats: []string{"json", "gitlab-sast"},
			want:    []string{"report.prod.json"},
		},
		{
			name:    "no format requested leaves the path as given",
			path:    "report.prod",
			formats: nil,
			want:    []string{"report.prod"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ElementsMatch(t, tt.want, printerDestinations(tt.path, tt.formats))
		})
	}
}

func TestPerContextOutputPaths_RejectsCollisionOnlyVisibleAfterFormatResolution(t *testing.T) {
	// Neither derived path collides on its own, "report.prod" and
	// "report.prod.json", but under --format json the first gains the
	// extension the second already has and both printers write one file.
	_, err := perContextOutputPaths("report", []string{"prod", "prod.json"}, []string{"json"})

	require.ErrorContains(t, err, "colliding")
	require.ErrorContains(t, err, "report.prod.json")
}

func TestValidateFleetReportPath_ComparesResolvedDestinations(t *testing.T) {
	paths, err := perContextOutputPaths("report", []string{"prod", "staging"}, []string{"json"})
	require.NoError(t, err)

	// The raw per-context path is "report.prod"; what actually gets written is
	// "report.prod.json", and that is what the fleet report must not name.
	require.ErrorContains(t, validateFleetReportPath("report.prod.json", paths, []string{"json"}), "prod")

	assert.NoError(t, validateFleetReportPath("fleet.json", paths, []string{"json"}))
}

func TestFleetScan_RejectsFleetReportCollidingAfterFormatResolution(t *testing.T) {
	dir := t.TempDir()
	ks := &fleetTrackingKubescape{}
	scanInfo := cautils.ScanInfo{
		KubeContexts: []string{"prod"},
		Output:       filepath.Join(dir, "report"),
		Format:       "json",
		FleetReport:  filepath.Join(dir, "report.prod.json"),
		ScanType:     cautils.ScanTypeCluster,
	}

	err := fleetScan(scanInfo, ks, nil, scanContextOnlyRunner)

	require.ErrorContains(t, err, "overwrite")
	assert.Empty(t, ks.callsOutputs, "the JSON printer would write report.prod.json, so this must be caught before scanning")
}

func TestFleetScan_RejectsFleetReportCollidingWithOneOfSeveralFormats(t *testing.T) {
	dir := t.TempDir()
	ks := &fleetTrackingKubescape{}
	scanInfo := cautils.ScanInfo{
		KubeContexts: []string{"prod"},
		Output:       filepath.Join(dir, "report"),
		Format:       "json,pdf,sarif",
		// Collides with the sarif destination only.
		FleetReport: filepath.Join(dir, "report.prod.sarif"),
		ScanType:    cautils.ScanTypeCluster,
	}

	err := fleetScan(scanInfo, ks, nil, scanContextOnlyRunner)

	require.ErrorContains(t, err, "overwrite")
	assert.Empty(t, ks.callsOutputs, "every requested format's destination has to be checked, not just the first")
}

func TestValidateKubeContextsSupported_FleetReportRejectsPrivacyModes(t *testing.T) {
	cmd := &cobra.Command{Use: "scan"}

	// The fleet envelope takes ClusterID, Context, Metadata.Contexts and every
	// matrix key from the raw kube context name, which neither mode touches,
	// and each context transforms with its own mapping or key so nothing could
	// be joined across clusters anyway.
	err := validateKubeContextsSupported(cmd, &cautils.ScanInfo{
		KubeContexts: []string{"prod", "staging"},
		FleetReport:  "fleet.json",
		Hide:         true,
	})
	require.ErrorContains(t, err, "--hide")

	err = validateKubeContextsSupported(cmd, &cautils.ScanInfo{
		KubeContexts:      []string{"prod", "staging"},
		FleetReport:       "fleet.json",
		EncryptionEnabled: true,
	})
	require.ErrorContains(t, err, "--encrypt")

	// Neither mode set is the ordinary fleet scan.
	securityView := string(cautils.SecurityViewType)
	assert.NoError(t, validateKubeContextsSupported(cmd, &cautils.ScanInfo{
		KubeContexts: []string{"prod", "staging"},
		FleetReport:  "fleet.json",
		View:         securityView,
	}))

	// Without --fleet-report the modes are untouched, since each context's own
	// report is transformed exactly as a single-cluster scan would be.
	assert.NoError(t, validateKubeContextsSupported(cmd, &cautils.ScanInfo{
		KubeContexts: []string{"prod", "staging"},
		Hide:         true,
		View:         securityView,
	}))
	assert.NoError(t, validateKubeContextsSupported(cmd, &cautils.ScanInfo{
		KubeContexts:      []string{"prod", "staging"},
		EncryptionEnabled: true,
		View:              securityView,
	}))
}

func TestFleetReportRequested_AgreesWithValidation(t *testing.T) {
	// The predicate validation and execution share. A whitespace-only value is
	// "requested", which is why validateFleetReportValue rejects it rather
	// than letting either side quietly treat it as absent.
	assert.False(t, fleetReportRequested(""))
	assert.True(t, fleetReportRequested(" "))
	assert.True(t, fleetReportRequested("fleet.json"))

	require.NoError(t, validateFleetReportValue(""))
	require.NoError(t, validateFleetReportValue("fleet.json"))
	require.ErrorContains(t, validateFleetReportValue(" "), "blank")
	require.ErrorContains(t, validateFleetReportValue("\t\n"), "blank")
}

func TestValidateKubeContextsSupported_RejectsBlankFleetReport(t *testing.T) {
	cmd := &cobra.Command{Use: "scan"}

	// --fleet-report " " used to read as absent here and as present in
	// fleetScan, so it slipped past the privacy check and then wrote a file
	// named " " full of the identifiers --hide had just removed.
	for _, scanInfo := range []*cautils.ScanInfo{
		{KubeContexts: []string{"prod"}, FleetReport: " ", Hide: true},
		{KubeContexts: []string{"prod"}, FleetReport: " ", EncryptionEnabled: true},
		{KubeContexts: []string{"prod"}, FleetReport: " "},
		{FleetReport: " "},
	} {
		require.ErrorContains(t, validateKubeContextsSupported(cmd, scanInfo), "blank")
	}
}

func TestFleetScan_BlankFleetReportScansNothingAndWritesNothing(t *testing.T) {
	dir := t.TempDir()
	ks := &fleetFileWritingKubescape{}
	scanInfo := cautils.ScanInfo{
		KubeContexts: []string{"prod", "staging"},
		Output:       filepath.Join(dir, "report.json"),
		FleetReport:  " ",
		ScanType:     cautils.ScanTypeCluster,
	}

	err := fleetScan(scanInfo, ks, nil, scanContextOnlyRunner)

	require.ErrorContains(t, err, "blank")
	assert.Empty(t, ks.callsOutputs, "no context may be scanned")
	entries, readErr := os.ReadDir(dir)
	require.NoError(t, readErr)
	assert.Empty(t, entries, "nothing may be written, least of all a file named \" \"")
}

func TestFleetScan_PrivacyModesRejectedBeforeAnyScanOrWrite(t *testing.T) {
	tests := []struct {
		name        string
		fleetReport string
		mutate      func(*cautils.ScanInfo)
		wantErr     string
	}{
		{
			name:        "hide",
			fleetReport: "fleet.json",
			mutate:      func(s *cautils.ScanInfo) { s.Hide = true },
			wantErr:     "--hide",
		},
		{
			name:        "encrypt",
			fleetReport: "fleet.json",
			mutate:      func(s *cautils.ScanInfo) { s.EncryptionEnabled = true },
			wantErr:     "--encrypt",
		},
		{
			// The bypass: blank reads as absent to a trimming check, so the
			// privacy guard never ran and the report was written anyway.
			name:        "hide with a blank fleet report path",
			fleetReport: " ",
			mutate:      func(s *cautils.ScanInfo) { s.Hide = true },
			wantErr:     "blank",
		},
		{
			name:        "encrypt with a blank fleet report path",
			fleetReport: " ",
			mutate:      func(s *cautils.ScanInfo) { s.EncryptionEnabled = true },
			wantErr:     "blank",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			ks := &fleetFileWritingKubescape{}
			scanInfo := cautils.ScanInfo{
				KubeContexts: []string{"prod", "staging"},
				Output:       filepath.Join(dir, "report.json"),
				ScanType:     cautils.ScanTypeCluster,
			}
			if tt.fleetReport == " " {
				scanInfo.FleetReport = " "
			} else {
				scanInfo.FleetReport = filepath.Join(dir, tt.fleetReport)
			}
			tt.mutate(&scanInfo)

			err := fleetScan(scanInfo, ks, nil, scanContextOnlyRunner)

			require.ErrorContains(t, err, tt.wantErr)
			assert.Empty(t, ks.callsOutputs, "a privacy mode must stop the run before any cluster is scanned")
			entries, readErr := os.ReadDir(dir)
			require.NoError(t, readErr)
			assert.Empty(t, entries, "no report of any kind may reach disk")
		})
	}
}

func TestResolvePath_AppliesDotDotAfterFollowingTheLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs elevated rights on windows")
	}
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "target", "sub"), 0o750))
	require.NoError(t, os.Symlink(filepath.Join(dir, "target", "sub"), filepath.Join(dir, "link")))

	// Built by concatenation, not filepath.Join, which would clean away the
	// "link/.." this test exists for.
	viaLink := dir + "/link/../report.prod.json"

	got, err := resolvePath(viaLink)
	require.NoError(t, err)

	// The kernel follows link to target/sub and only then applies "..", so the
	// path names target/report.prod.json. Cleaning first would say the temp
	// directory instead, which is a different file.
	want, err := resolvePath(filepath.Join(dir, "target", "report.prod.json"))
	require.NoError(t, err)
	assert.Equal(t, want, got)
	assert.NotEqual(t, filepath.Join(dir, "report.prod.json"), got,
		"lexical cleaning would land here, which is the bug")
}

func TestResolvePath_Forms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs elevated rights on windows")
	}
	dir, err := resolvePath(t.TempDir()) // the temp root may itself sit under a link
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "real", "sub"), 0o750))
	require.NoError(t, os.Symlink(filepath.Join(dir, "real"), filepath.Join(dir, "absLink")))
	require.NoError(t, os.Symlink("real/sub", filepath.Join(dir, "relLink")))
	require.NoError(t, os.Symlink(filepath.Join(dir, "real", "missing"), filepath.Join(dir, "dangling")))

	tests := []struct {
		name string
		path string
		want string
	}{
		{"plain path that does not exist", dir + "/real/fleet.json", filepath.Join(dir, "real", "fleet.json")},
		{"symlinked parent", dir + "/absLink/fleet.json", filepath.Join(dir, "real", "fleet.json")},
		{"relative link target", dir + "/relLink/fleet.json", filepath.Join(dir, "real", "sub", "fleet.json")},
		{"dot dot after a relative link", dir + "/relLink/../fleet.json", filepath.Join(dir, "real", "fleet.json")},
		{"dot dot after an absolute link", dir + "/absLink/../fleet.json", filepath.Join(dir, "fleet.json")},
		{"dangling link is its target", dir + "/dangling", filepath.Join(dir, "real", "missing")},
		{"single dot segments", dir + "/./real/./fleet.json", filepath.Join(dir, "real", "fleet.json")},
		{"repeated separators", dir + "//real///fleet.json", filepath.Join(dir, "real", "fleet.json")},
		{"missing directory that will be created", dir + "/new/deeper/fleet.json", filepath.Join(dir, "new", "deeper", "fleet.json")},
		{"dot dot beneath a missing directory", dir + "/new/../fleet.json", filepath.Join(dir, "fleet.json")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolvePath(tt.path)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestResolvePath_RejectsCycles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs elevated rights on windows")
	}
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	require.NoError(t, os.Symlink(b, a))
	require.NoError(t, os.Symlink(a, b))

	_, err := resolvePath(a)
	require.ErrorContains(t, err, "symbolic links")
}

func TestResolvePath_RelativePathResolvesAgainstTheWorkingDirectory(t *testing.T) {
	abs, err := resolvePath("fleet.json")
	require.NoError(t, err)
	assert.True(t, filepath.IsAbs(abs))

	cwd, err := os.Getwd()
	require.NoError(t, err)
	viaAbs, err := resolvePath(filepath.Join(cwd, "fleet.json"))
	require.NoError(t, err)
	assert.Equal(t, viaAbs, abs, "the same file named two ways must resolve equal")
}

func TestFleetScan_RejectsDotDotThroughSymlinkWhenTheContextFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs elevated rights on windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.MkdirAll(filepath.Join(target, "sub"), 0o750))
	require.NoError(t, os.Symlink(filepath.Join(target, "sub"), filepath.Join(dir, "link")))

	// prod fails, so target/report.prod.json is never written and neither
	// os.SameFile side has a file to compare. Only resolving the components in
	// the order the kernel does catches that link/.. reaches the reserved path.
	ks := &fleetOutcomeKubescape{outcomes: map[string]func() (*resultshandling.ResultsHandler, error){
		"prod": func() (*resultshandling.ResultsHandler, error) { return nil, errors.New("no route to host") },
	}}
	scanInfo := cautils.ScanInfo{
		KubeContexts: []string{"prod"},
		Output:       filepath.Join(target, "report.json"),
		// Raw string on purpose: filepath.Join would clean away the trigger.
		FleetReport: dir + "/link/../report.prod.json",
		ScanType:    cautils.ScanTypeCluster,
	}

	err := fleetScan(scanInfo, ks, nil, scanContextOnlyRunner)

	require.ErrorContains(t, err, "resolves to the per-context report")
	assert.NoFileExists(t, filepath.Join(target, "report.prod.json"),
		"fleet JSON must not be created at the path reserved for prod's own report")
}

func TestValidateKubeContextsSupported_FleetReportRequiresKubeContexts(t *testing.T) {
	cmd := &cobra.Command{Use: "scan"}

	err := validateKubeContextsSupported(cmd, &cautils.ScanInfo{FleetReport: "fleet.json"})
	require.ErrorContains(t, err, "--fleet-report requires --kube-contexts")

	assert.NoError(t, validateKubeContextsSupported(cmd, &cautils.ScanInfo{}), "neither flag set is the ordinary single-cluster scan")
}
