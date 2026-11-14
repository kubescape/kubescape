package core

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/diff"
	"github.com/kubescape/kubescape/v4/core/pkg/watch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestLocalScanner(t *testing.T, dir string) *LocalScanner {
	t.Helper()
	scanner, err := (&Kubescape{Ctx: context.Background()}).NewLocalScanner(localScanTemplate(t, dir), readOnlyRootFilesystem)
	require.NoError(t, err)
	return scanner
}

// A series of scans sees the manifests as they are at each scan, and each result
// is the report ScanToReport makes of the same input.
func TestLocalScannerSeriesSeesEachChange(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "pod.yaml", podManifest("web", false))
	scanner := newTestLocalScanner(t, dir)

	first, err := scanner.Scan(context.Background(), LocalInput{})
	require.NoError(t, err)
	firstJSON, err := first.JSON()
	require.NoError(t, err)

	writeManifest(t, dir, "pod.yaml", podManifest("web", true))
	second, err := scanner.Scan(context.Background(), LocalInput{Paths: []string{dir}})
	require.NoError(t, err)
	secondJSON, err := second.JSON()
	require.NoError(t, err)

	comparison, err := watch.Compare(firstJSON, secondJSON, diff.Options{Granularity: diff.GranularityControl})
	require.NoError(t, err)
	assert.NotEmpty(t, comparison.ChangeSet.Resolved, "the fix is seen by the second scan")
	assert.Empty(t, comparison.ChangeSet.New)
	assert.NotNil(t, second.Session)
	assert.False(t, second.Degraded)
}

func TestLocalScannerJSONEqualsScanToReportAndIsMemoized(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "pod.yaml", podManifest("web", false))
	ks := &Kubescape{Ctx: context.Background()}
	scanner := newTestLocalScanner(t, dir)

	result, err := scanner.Scan(context.Background(), LocalInput{})
	require.NoError(t, err)
	got, err := result.JSON()
	require.NoError(t, err)
	again, err := result.JSON()
	require.NoError(t, err)
	assert.Same(t, &got[0], &again[0], "the same bytes are returned")

	report, err := ks.ScanToReport(context.Background(), localScanTemplate(t, dir), readOnlyRootFilesystem)
	require.NoError(t, err)
	comparison, err := watch.Compare(report.JSON, got, diff.Options{Granularity: diff.GranularityControl})
	require.NoError(t, err)
	assert.Empty(t, comparison.ChangeSet.New)
	assert.Empty(t, comparison.ChangeSet.Resolved)
	assert.NotEmpty(t, comparison.ChangeSet.Unchanged)
	assert.Equal(t, report.Degraded, result.Degraded)
}

func TestLocalScannerConcurrentScans(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	pointKubeconfigAt(t, server.URL)
	dir := t.TempDir()
	writeManifest(t, dir, "pod.yaml", podManifest("web", false))
	scanner := newTestLocalScanner(t, dir)

	const scans = 6
	var wg sync.WaitGroup
	jsons := make([][]byte, scans)
	errs := make([]error, scans)
	for i := 0; i < scans; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := scanner.Scan(context.Background(), LocalInput{})
			if err != nil {
				errs[i] = err
				return
			}
			jsons[i], errs[i] = result.JSON()
		}()
	}
	wg.Wait()

	for i := range errs {
		require.NoError(t, errs[i], "scan %d", i)
		comparison, err := watch.Compare(jsons[0], jsons[i], diff.Options{Granularity: diff.GranularityControl})
		require.NoError(t, err)
		assert.Empty(t, comparison.ChangeSet.New, "scan %d", i)
		assert.Empty(t, comparison.ChangeSet.Resolved, "scan %d", i)
	}
	assert.Zero(t, requests.Load(), "no scan reached for the cluster")
}

func TestLocalScannerEndOfContextKeepsItsCause(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "pod.yaml", podManifest("web", false))
	scanner := newTestLocalScanner(t, dir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := scanner.Scan(ctx, LocalInput{})
	require.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, result)

	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	result, err = scanner.Scan(ctx, LocalInput{})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Nil(t, result)
}

func TestLocalScannerInvalidInput(t *testing.T) {
	ks := &Kubescape{Ctx: context.Background()}

	t.Run("no scan info", func(t *testing.T) {
		scanner, err := ks.NewLocalScanner(nil, readOnlyRootFilesystem)
		require.Error(t, err)
		assert.Nil(t, scanner)
	})
	t.Run("no path", func(t *testing.T) {
		template := localScanTemplate(t, t.TempDir())
		template.InputPatterns = nil
		scanner, err := ks.NewLocalScanner(template, readOnlyRootFilesystem)
		require.NoError(t, err)
		result, err := scanner.Scan(context.Background(), LocalInput{})
		require.Error(t, err)
		assert.Nil(t, result)
	})
}

func TestLocalScannerRefusesWhatCannotBeReturnedInMemory(t *testing.T) {
	ks := &Kubescape{Ctx: context.Background()}
	dir := t.TempDir()
	t.Run("dry run", func(t *testing.T) {
		info := localScanTemplate(t, dir)
		info.DryRun = true
		_, err := ks.NewLocalScanner(info, readOnlyRootFilesystem)
		require.ErrorIs(t, err, ErrUnsupportedScan)
	})
	t.Run("encryption", func(t *testing.T) {
		info := localScanTemplate(t, dir)
		info.EncryptionEnabled = true
		_, err := ks.NewLocalScanner(info, readOnlyRootFilesystem)
		require.ErrorIs(t, err, ErrUnsupportedScan)
	})
	t.Run("image scan", func(t *testing.T) {
		info := localScanTemplate(t, dir)
		info.ScanImages = true
		_, err := ks.NewLocalScanner(info, readOnlyRootFilesystem)
		require.ErrorIs(t, err, ErrUnsupportedScan)
	})
}

func TestLocalScannerReturnsAScanFailureAsAnError(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "pod.yaml", podManifest("web", false))
	template := localScanTemplate(t, dir)
	template.UseFrom = []string{filepath.Join(t.TempDir(), "missing-policy.json")}
	scanner, err := (&Kubescape{Ctx: context.Background()}).NewLocalScanner(template, readOnlyRootFilesystem)
	require.NoError(t, err)

	result, err := scanner.Scan(context.Background(), LocalInput{})
	require.Error(t, err)
	assert.Nil(t, result)
}

func TestLocalScannerDoesNotChangeTheCallersScanInfo(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "pod.yaml", podManifest("web", false))
	template := localScanTemplate(t, dir)
	template.Local = false
	template.Format = "json"
	template.MinSeverity = "high"
	scanner, err := (&Kubescape{Ctx: context.Background()}).NewLocalScanner(template, readOnlyRootFilesystem)
	require.NoError(t, err)

	_, err = scanner.Scan(context.Background(), LocalInput{Paths: []string{dir}})
	require.NoError(t, err)

	assert.False(t, template.Local)
	assert.Equal(t, "json", template.Format)
	assert.Equal(t, "high", template.MinSeverity)
	assert.Nil(t, template.ReleasedPolicyStore)
	assert.Equal(t, []string{dir}, template.InputPatterns)
}

// A caller that prints its own output, or speaks a protocol on stdout, is not
// written to by a scan.
func TestLocalScannerWritesNothingToStdout(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "pod.yaml", podManifest("web", false))
	scanner := newTestLocalScanner(t, dir)

	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	original := os.Stdout
	os.Stdout = writer
	captured := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(reader)
		captured <- data
	}()
	result, scanErr := scanner.Scan(context.Background(), LocalInput{})
	if scanErr == nil {
		_, scanErr = result.JSON()
	}
	os.Stdout = original
	require.NoError(t, writer.Close())

	require.NoError(t, scanErr)
	assert.Empty(t, string(<-captured))
}

// A ScanInfo asked for its scanning context before it had inputs has cached the
// cluster as it. The scanner's copy is told the paths it scans, and works the
// context out from them; the caller's keeps what it cached.
func TestLocalScannerWorksOutTheScanningContextFromThePathsItScans(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "pod.yaml", podManifest("web", false))
	template := localScanTemplate(t, dir)
	template.InputPatterns = nil
	require.Equal(t, cautils.ContextCluster, template.GetScanningContext(), "the base caches the cluster as its context")
	scanner, err := (&Kubescape{Ctx: context.Background()}).NewLocalScanner(template, readOnlyRootFilesystem)
	require.NoError(t, err)

	result, err := scanner.Scan(context.Background(), LocalInput{Paths: []string{dir}})

	require.NoError(t, err)
	require.NotErrorIs(t, err, ErrUnsupportedScan)
	reportJSON, err := result.JSON()
	require.NoError(t, err)
	assert.NotEmpty(t, failedResources(t, reportJSON), "the manifest was scanned")
	assert.Equal(t, cautils.ContextCluster, template.GetScanningContext(), "the caller's ScanInfo keeps its cache")
	assert.Empty(t, template.InputPatterns)
}

// A scan that streams its resources reaches for the cluster as the eager scan
// does unless it is told not to: it hands the kubeconfig to the rules and asks
// the API server whether it may create events.
func TestStreamingScanHonorsNoClusterAccess(t *testing.T) {
	for _, tc := range []struct {
		name            string
		noClusterAccess bool
		reachesCluster  bool
	}{
		{"no cluster access", true, false},
		{"cluster access", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				http.NotFound(w, r)
			}))
			t.Cleanup(server.Close)
			pointKubeconfigAt(t, server.URL)
			scanInfo := &cautils.ScanInfo{NoClusterAccess: tc.noClusterAccess}

			err := collectAndProcessResourcesWithStreaming(context.Background(), &streamingCancelMock{}, cautils.NewOPASessionObjMock(), scanInfo, "cluster", "", "", false, time.Second, 10)

			require.NoError(t, err)
			if tc.reachesCluster {
				assert.NotZero(t, requests.Load(), "the check reaches the fake API server, so the other case proves something")
			} else {
				assert.Zero(t, requests.Load(), "the scan did not reach the cluster")
			}
		})
	}
}

// The scanner keeps its promise of no cluster when it streams.
func TestLocalScannerWithStreamingDoesNotContactTheCluster(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	pointKubeconfigAt(t, server.URL)
	dir := t.TempDir()
	writeManifest(t, dir, "pod.yaml", podManifest("web", false))
	template := localScanTemplate(t, dir)
	template.NoClusterAccess = false // the scanner sets it itself
	template.EnableStreaming = true
	scanner, err := (&Kubescape{Ctx: context.Background()}).NewLocalScanner(template, readOnlyRootFilesystem)
	require.NoError(t, err)

	result, err := scanner.Scan(context.Background(), LocalInput{})

	require.NoError(t, err)
	reportJSON, err := result.JSON()
	require.NoError(t, err)
	assert.NotEmpty(t, failedResources(t, reportJSON))
	assert.Zero(t, requests.Load(), "the scan did not reach the cluster")
}
