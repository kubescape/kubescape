package scan

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/meta"
	"github.com/kubescape/kubescape/v4/core/pkg/fleet"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// attemptOutcome is what one scan attempt of a context returns.
type attemptOutcome func() (*resultshandling.ResultsHandler, error)

// retryRunner is a fleetRunner that answers each attempt with the next outcome, repeating the last, and records its settings.
type retryRunner struct {
	mu       sync.Mutex
	outcomes map[string][]attemptOutcome
	attempts map[string][]*cautils.ScanInfo
}

// newRetryRunner returns a retryRunner answering each context from outcomes.
func newRetryRunner(outcomes map[string][]attemptOutcome) *retryRunner {
	return &retryRunner{outcomes: outcomes, attempts: map[string][]*cautils.ScanInfo{}}
}

// run answers the next attempt of the context it is asked to scan and records the settings that attempt was given.
func (r *retryRunner) run(_ context.Context, scanInfo *cautils.ScanInfo, _ meta.IKubescape, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := scanInfo.GetClusterContextName()
	attempt := len(r.attempts[name])
	r.attempts[name] = append(r.attempts[name], scanInfo)
	outcomes := r.outcomes[name]
	return outcomes[min(attempt, len(outcomes)-1)]()
}

// calls is how many attempts the context has had so far.
func (r *retryRunner) calls(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.attempts[name])
}

// refused is an attempt that finds nothing listening at the API server.
func refused() (*resultshandling.ResultsHandler, error) { return nil, refusedConnection("prod") }

// scannedCleanly is an attempt that completes and passes.
func scannedCleanly() (*resultshandling.ResultsHandler, error) {
	return resultsWithControl(apis.StatusPassed, 100), nil
}

// noRetryWait removes the wait between attempts, so a test exercises the retry decisions without sleeping.
func noRetryWait(t *testing.T) {
	t.Helper()
	original := fleetRetryDelay
	fleetRetryDelay = func(int) time.Duration { return 0 }
	t.Cleanup(func() { fleetRetryDelay = original })
}

// retryScanInfo is a fleet scan of prod alone with the given number of retries, with or without a fleet report.
func retryScanInfo(t *testing.T, retries int, withFleetReport bool) cautils.ScanInfo {
	t.Helper()
	dir := t.TempDir()
	scanInfo := cautils.ScanInfo{
		KubeContexts:       []string{"prod"},
		Output:             filepath.Join(dir, "report.json"),
		ScanType:           cautils.ScanTypeCluster,
		KubeContextRetries: retries,
	}
	if withFleetReport {
		scanInfo.FleetReport = filepath.Join(dir, "fleet.json")
	}
	return scanInfo
}

// prodResult reads prod's entry back from the fleet report the scan wrote.
func prodResult(t *testing.T, scanInfo cautils.ScanInfo) fleet.ClusterResult {
	t.Helper()
	report := fleetReportFromFile(t, scanInfo.FleetReport)
	require.Len(t, report.Clusters, 1)
	return report.Clusters[0]
}

// TestRetryDelay pins the wait schedule: 2s, doubling, capped at 30s, and never overflowing.
func TestRetryDelay(t *testing.T) {
	tests := []struct {
		retry int
		want  time.Duration
	}{
		{retry: 1, want: 2 * time.Second},
		{retry: 2, want: 4 * time.Second},
		{retry: 3, want: 8 * time.Second},
		{retry: 4, want: 16 * time.Second},
		{retry: 5, want: 30 * time.Second},
		{retry: 1000, want: 30 * time.Second},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, retryDelay(tt.retry), "retry %d", tt.retry)
	}
}

// TestFleetScan_RetriesAnUnreachableClusterUntilItAnswers covers a cluster that is down for a moment and then answers.
func TestFleetScan_RetriesAnUnreachableClusterUntilItAnswers(t *testing.T) {
	noRetryWait(t)
	scanInfo := retryScanInfo(t, 2, true)
	runner := newRetryRunner(map[string][]attemptOutcome{"prod": {refused, scannedCleanly}})

	require.NoError(t, fleetScan(scanInfo, &fleetTrackingKubescape{}, nil, runner.run))

	assert.Equal(t, 2, runner.calls("prod"))
	got := prodResult(t, scanInfo)
	assert.Equal(t, fleet.ClusterScanned, got.Status)
	assert.Equal(t, 2, got.Attempts)
}

// TestFleetScan_GivesUpAfterTheRetryBudget pins that retries are bounded and a cluster still down ends unreachable.
func TestFleetScan_GivesUpAfterTheRetryBudget(t *testing.T) {
	noRetryWait(t)
	scanInfo := retryScanInfo(t, 2, true)
	runner := newRetryRunner(map[string][]attemptOutcome{"prod": {refused}})

	err := fleetScan(scanInfo, &fleetTrackingKubescape{}, nil, runner.run)

	require.ErrorContains(t, err, "after 3 attempts")
	assert.Equal(t, 3, runner.calls("prod"), "two retries means three attempts in all")
	got := prodResult(t, scanInfo)
	assert.Equal(t, fleet.ClusterUnreachable, got.Status)
	assert.Equal(t, 3, got.Attempts)
	assert.Contains(t, got.Error, "connection refused")
	assert.NotContains(t, got.Error, "attempts", "the cluster's error is kept verbatim; the attempt count has its own field")
}

// TestFleetScan_RetriesOnlyUnreachableClusters pins that every other outcome is final.
func TestFleetScan_RetriesOnlyUnreachableClusters(t *testing.T) {
	noRetryWait(t)
	forbidden := apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New("rbac"))
	tests := map[string]attemptOutcome{
		"scan failed inside": func() (*resultshandling.ResultsHandler, error) {
			return nil, errors.New("policy download failed")
		},
		"server refused the request": func() (*resultshandling.ResultsHandler, error) {
			return nil, collectionFailure{forbidden}
		},
		"server answered another query": func() (*resultshandling.ResultsHandler, error) {
			return nil, answeredCollection{collectionFailure{connectionRefused("prod")}}
		},
		"scanned but breached a threshold": func() (*resultshandling.ResultsHandler, error) {
			return resultsWithControl(apis.StatusFailed, 40), errors.New("scan compliance-score is below permitted threshold")
		},
		"scanned alongside an error that looks unreachable": func() (*resultshandling.ResultsHandler, error) {
			return resultsWithControl(apis.StatusPassed, 100), refusedConnection("prod")
		},
	}

	for name, outcome := range tests {
		t.Run(name, func(t *testing.T) {
			scanInfo := retryScanInfo(t, 2, true)
			runner := newRetryRunner(map[string][]attemptOutcome{"prod": {outcome}})

			require.Error(t, fleetScan(scanInfo, &fleetTrackingKubescape{}, nil, runner.run))

			assert.Equal(t, 1, runner.calls("prod"), "only a cluster that never answered is worth trying again")
			assert.Equal(t, 1, prodResult(t, scanInfo).Attempts)
		})
	}
}

// TestFleetScan_DoesNotRetryACancelledScan pins that a run the operator stopped is not started again.
func TestFleetScan_DoesNotRetryACancelledScan(t *testing.T) {
	noRetryWait(t)
	scanInfo := retryScanInfo(t, 2, true)
	stopped, cancel := context.WithCancel(context.Background())
	cancel()
	runner := newRetryRunner(map[string][]attemptOutcome{"prod": {refused}})

	require.Error(t, fleetScan(scanInfo, &lifecycleContextKubescape{ctx: stopped}, nil, runner.run))

	assert.Zero(t, runner.calls("prod"), "a run that is already stopped never starts the scan")
	assert.Equal(t, fleet.ClusterCancelled, prodResult(t, scanInfo).Status)
}

// TestFleetScan_StopsWaitingAsSoonAsTheRunIsStopped pins that Ctrl-C during the wait takes effect at once and skips later contexts.
func TestFleetScan_StopsWaitingAsSoonAsTheRunIsStopped(t *testing.T) {
	running, cancel := context.WithCancel(context.Background())
	defer cancel()
	original := fleetRetryDelay
	fleetRetryDelay = func(int) time.Duration {
		// The attempt is already classified when a wait is chosen, so stopping now lands inside the wait.
		time.AfterFunc(50*time.Millisecond, cancel)
		return time.Hour
	}
	t.Cleanup(func() { fleetRetryDelay = original })

	scanInfo := retryScanInfo(t, 2, true)
	scanInfo.KubeContexts = []string{"prod", "staging"}
	runner := newRetryRunner(map[string][]attemptOutcome{"prod": {refused}, "staging": {scannedCleanly}})

	started := time.Now()
	require.Error(t, fleetScan(scanInfo, &lifecycleContextKubescape{ctx: running}, nil, runner.run))

	assert.Less(t, time.Since(started), 10*time.Second, "an hour-long wait has to end when the run is stopped")
	assert.Equal(t, 1, runner.calls("prod"))
	assert.Zero(t, runner.calls("staging"), "a context after the stop never starts its scan")
	report := fleetReportFromFile(t, scanInfo.FleetReport)
	require.Len(t, report.Clusters, 2)
	assert.Equal(t, fleet.ClusterUnreachable, report.Clusters[0].Status, "the attempt that ran found the cluster unreachable, and that is what it keeps")
	assert.Equal(t, 1, report.Clusters[0].Attempts)
	assert.Equal(t, fleet.ClusterCancelled, report.Clusters[1].Status)
}

// TestFleetScan_RetriesWithoutAFleetReport pins that retries belong to --kube-contexts, not to --fleet-report.
func TestFleetScan_RetriesWithoutAFleetReport(t *testing.T) {
	noRetryWait(t)
	scanInfo := retryScanInfo(t, 2, false)
	runner := newRetryRunner(map[string][]attemptOutcome{"prod": {refused, scannedCleanly}})

	require.NoError(t, fleetScan(scanInfo, &fleetTrackingKubescape{}, nil, runner.run))

	assert.Equal(t, 2, runner.calls("prod"))
}

// TestFleetScan_ZeroRetriesTriesOnce pins that --retries 0 turns retries off.
func TestFleetScan_ZeroRetriesTriesOnce(t *testing.T) {
	noRetryWait(t)
	scanInfo := retryScanInfo(t, 0, true)
	runner := newRetryRunner(map[string][]attemptOutcome{"prod": {refused}})

	err := fleetScan(scanInfo, &fleetTrackingKubescape{}, nil, runner.run)

	require.Error(t, err)
	assert.NotContains(t, err.Error(), "attempts", "a single attempt needs no count")
	assert.Equal(t, 1, runner.calls("prod"))
	assert.Equal(t, 1, prodResult(t, scanInfo).Attempts)
}

// TestScanFleetContext_EachAttemptStartsFresh pins that an attempt never sees what the previous one changed.
func TestScanFleetContext_EachAttemptStartsFresh(t *testing.T) {
	noRetryWait(t)
	previousContext := k8sinterface.GetContextName()
	t.Cleanup(func() { k8sinterface.SetClusterContextName(previousContext) })

	base := retryScanInfo(t, 2, false)
	base.UseFrom = []string{"framework.json"}
	var activeContexts []string
	runner := newRetryRunner(map[string][]attemptOutcome{"prod": {
		func() (*resultshandling.ResultsHandler, error) {
			activeContexts = append(activeContexts, k8sinterface.GetContextName())
			return refused()
		},
		func() (*resultshandling.ResultsHandler, error) {
			activeContexts = append(activeContexts, k8sinterface.GetContextName())
			return scannedCleanly()
		},
	}})
	mutating := func(ctx context.Context, scanInfo *cautils.ScanInfo, ks meta.IKubescape, policies []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
		results, err := runner.run(ctx, scanInfo, ks, policies)
		scanInfo.UseFrom = append(scanInfo.UseFrom, "added by the scan")
		scanInfo.ScanID = "used"
		return results, err
	}

	_, _, attempts, err := scanFleetContext("prod", base.Output, &base, &fleetTrackingKubescape{}, nil, mutating)

	require.NoError(t, err)
	require.Equal(t, 2, attempts)
	seen := runner.attempts["prod"]
	require.Len(t, seen, 2)
	assert.NotSame(t, seen[0], seen[1], "every attempt gets its own copy of the settings")
	assert.Equal(t, []string{"framework.json", "added by the scan"}, seen[1].UseFrom, "the second attempt starts from the base, not from what the first attempt left behind")
	assert.Equal(t, []string{"framework.json"}, base.UseFrom, "the base settings are never changed by an attempt")
	assert.Equal(t, []string{"prod", "prod"}, activeContexts, "every attempt runs against the cluster it is retrying")
}

// TestValidateRetries pins the flag checks, and that the default never gets in the way of an ordinary scan.
func TestValidateRetries(t *testing.T) {
	withFlag := func(value string) *cobra.Command {
		cmd := &cobra.Command{Use: "scan"}
		var retries int
		cmd.Flags().IntVar(&retries, "retries", 2, "")
		if value != "" {
			require.NoError(t, cmd.Flags().Set("retries", value))
		}
		return cmd
	}

	require.ErrorContains(t,
		validateKubeContextsSupported(withFlag("-1"), &cautils.ScanInfo{KubeContexts: []string{"prod"}, KubeContextRetries: -1}),
		"--retries -1 is negative")
	require.ErrorContains(t,
		validateKubeContextsSupported(withFlag("3"), &cautils.ScanInfo{KubeContextRetries: 3}),
		"--retries requires --kube-contexts")
	assert.NoError(t,
		validateKubeContextsSupported(withFlag("3"), &cautils.ScanInfo{KubeContexts: []string{"prod"}, KubeContextRetries: 3, View: string(cautils.SecurityViewType)}))
	assert.NoError(t,
		validateKubeContextsSupported(withFlag(""), &cautils.ScanInfo{KubeContextRetries: 2}),
		"the default must not get in the way of an ordinary single-cluster scan")
}
