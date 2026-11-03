package v1

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	utilsapisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetPrometheusDefaultScanCommand(t *testing.T) {
	tests := []struct {
		name             string
		frameworksParam  string
		wantScanAll      bool
		wantFrameworkIDs []string
	}{
		{
			name:        "default behavior - scan all frameworks",
			wantScanAll: true,
		},
		{
			name:             "specific frameworks via query parameter",
			frameworksParam:  "nsa,mitre,cis-v1.10.0",
			wantFrameworkIDs: []string{"nsa", "mitre", "cis-v1.10.0"},
		},
		{
			name:            "empty framework entries fall back to scanning all",
			frameworksParam: " , , ",
			wantScanAll:     true,
		},
		{
			name:             "specific frameworks ignore empty entries",
			frameworksParam:  "nsa, , mitre",
			wantFrameworkIDs: []string{"nsa", "mitre"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanID := "1234"
			outputFile := filepath.Join(OutputDir, scanID)
			scanInfo, policyIdentifiers := getPrometheusDefaultScanCommand(scanID, outputFile, tt.frameworksParam)

			assert.Equal(t, scanID, scanInfo.ScanID)
			assert.Equal(t, outputFile, scanInfo.Output)
			assert.Equal(t, "prometheus", scanInfo.Format)
			assert.False(t, scanInfo.Submit.GetBool())
			assert.True(t, scanInfo.Local)
			assert.True(t, scanInfo.FrameworkScan)
			assert.Equal(t, tt.wantScanAll, scanInfo.ScanAll)
			assert.False(t, scanInfo.HostSensorEnabled.GetBool())
			assert.Equal(t, getter.DefaultLocalStore, scanInfo.UseArtifactsFrom)
			assert.Len(t, policyIdentifiers, len(tt.wantFrameworkIDs))

			for i, wantFrameworkID := range tt.wantFrameworkIDs {
				assert.Equal(t, wantFrameworkID, policyIdentifiers[i].Identifier)
			}
		})
	}
}

// TestMetrics_ClientDisconnectCancelsScan ensures the metrics scan is aborted
// when the scrape request context is cancelled (e.g. a Prometheus scrape timeout)
// so abandoned scrapes do not continue consuming scan worker resources.
func TestMetrics_ClientDisconnectCancelsScan(t *testing.T) {
	withTempOutputDirs(t)
	synctest.Test(t, func(t *testing.T) {
		defer func(o scanner) { scanImpl = o }(scanImpl)
		scanCtxErr := make(chan error, 1)

		reqCtx, cancel := context.WithCancel(context.Background())
		scanImpl = func(ctx context.Context, _ *cautils.ScanInfo, _ []cautils.PolicyIdentifier, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
			cancel() // simulate the scrape connection going away mid-scan
			<-ctx.Done()
			scanCtxErr <- ctx.Err()
			return nil, ctx.Err()
		}

		h := NewHTTPHandler(false)
		rq := httptest.NewRequest(http.MethodGet, "/v1/metrics", nil).WithContext(reqCtx)
		w := httptest.NewRecorder()

		handlerDone := make(chan struct{})
		go func() {
			h.Metrics(w, rq)
			close(handlerDone)
		}()

		select {
		case err := <-scanCtxErr:
			assert.ErrorIs(t, err, context.Canceled, "scan context must be cancelled when the request context is")
		case <-time.After(5 * time.Second):
			t.Fatal("scan was not invoked")
		}

		select {
		case <-handlerDone:
		case <-time.After(5 * time.Second):
			t.Fatal("handler did not complete")
		}
		assert.NoError(t, h.Shutdown(context.Background(), time.Second))
		// Join response cleanup before the next test changes the output directories.
		synctest.Wait()
		assert.Zero(t, len(h.metricsScanSlot), "an abandoned scrape must release the metrics slot once its scan ends")
	})
}

// TestMetrics_ClientDisconnectSkipsQueuedScan ensures that a queued metrics scan
// is skipped if the client disconnects before the worker picks it up.
func TestMetrics_ClientDisconnectSkipsQueuedScan(t *testing.T) {
	withTempOutputDirs(t)
	synctest.Test(t, func(t *testing.T) {
		defer func(o scanner) { scanImpl = o }(scanImpl)

		var once sync.Once
		firstScanStarted := make(chan struct{})
		firstScanRelease := make(chan struct{})
		var secondScanInvoked atomic.Bool

		scanImpl = func(ctx context.Context, _ *cautils.ScanInfo, _ []cautils.PolicyIdentifier, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
			var wasFirst bool
			once.Do(func() {
				wasFirst = true
				close(firstScanStarted)
			})
			if wasFirst {
				<-firstScanRelease
				return nil, nil
			}
			secondScanInvoked.Store(true)
			return nil, nil
		}

		h := NewHTTPHandler(false)

		// Start first scan to keep worker busy
		go func() {
			w := httptest.NewRecorder()
			rq := httptest.NewRequest(http.MethodPost, "/v1/scan?wait=true", strings.NewReader(`{}`))
			h.Scan(w, rq)
		}()

		<-firstScanStarted

		// Second request arrives for /v1/metrics and gets queued
		reqCtx, cancel := context.WithCancel(context.Background())
		metricsDone := make(chan struct{})
		go func() {
			w := httptest.NewRecorder()
			rq := httptest.NewRequest(http.MethodGet, "/v1/metrics", nil).WithContext(reqCtx)
			h.Metrics(w, rq)
			close(metricsDone)
		}()

		// Client disconnects while queued
		cancel()

		select {
		case <-metricsDone:
		case <-time.After(5 * time.Second):
			t.Fatal("metrics handler did not unblock on cancellation")
		}

		// Release first scan so worker can dequeue second scan
		close(firstScanRelease)

		assert.NoError(t, h.Shutdown(context.Background(), time.Second))
		synctest.Wait()

		assert.False(t, secondScanInvoked.Load(), "queued metrics scan must be skipped when client disconnected")
		assert.Zero(t, len(h.metricsScanSlot), "a skipped metrics scan must release the metrics slot")
	})
}

func TestMetrics_UsesDecodedSkipPersistenceQueryParam(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{name: "absent", raw: "", want: false},
		{name: "lowercase true", raw: "true", want: true},
		{name: "titlecase true", raw: "True", want: true},
		{name: "numeric true", raw: "1", want: true},
		{name: "lowercase false", raw: "false", want: false},
		{name: "titlecase false", raw: "False", want: false},
		{name: "numeric false", raw: "0", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withTempOutputDirs(t)

			defer func(o scanner) { scanImpl = o }(scanImpl)
			gotSkipPersistence := make(chan bool, 1)
			scanImpl = func(_ context.Context, scanInfo *cautils.ScanInfo, _ []cautils.PolicyIdentifier, _ string, skipPersistence bool) (*reporthandlingv2.PostureReport, error) {
				gotSkipPersistence <- skipPersistence
				resolved, _ := printer.ResolveOutputFile(printer.PrometheusFormat, scanInfo.Output, "")
				require.NoError(t, os.WriteFile(resolved, []byte("# metrics\n"), 0o600))
				return nil, nil
			}

			h := NewHTTPHandler(false)
			target := "/v1/metrics"
			if tt.raw != "" {
				target += "?skipPersistence=" + url.QueryEscape(tt.raw)
			}
			rq := httptest.NewRequest(http.MethodGet, target, nil)
			w := httptest.NewRecorder()

			h.Metrics(w, rq)

			require.Equal(t, http.StatusOK, w.Result().StatusCode)
			select {
			case got := <-gotSkipPersistence:
				assert.Equal(t, tt.want, got)
			case <-time.After(5 * time.Second):
				t.Fatal("scan was not invoked")
			}
		})
	}
}

func TestMetrics_ReadsResultsFileWithPrometheusExtension(t *testing.T) {
	withTempOutputDirs(t)

	defer func(o scanner) { scanImpl = o }(scanImpl)
	scanImpl = func(_ context.Context, scanInfo *cautils.ScanInfo, _ []cautils.PolicyIdentifier, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
		// resolve the path the prometheus printer writes to, then write there
		resolved, _ := printer.ResolveOutputFile(printer.PrometheusFormat, scanInfo.Output, "")
		require.NoError(t, os.WriteFile(resolved, []byte("# metrics\n"), 0o600))
		return nil, nil
	}

	h := NewHTTPHandler(false)
	rq := httptest.NewRequest(http.MethodGet, "/v1/metrics?skipPersistence=true", nil)
	w := httptest.NewRecorder()

	h.Metrics(w, rq)

	require.Equal(t, http.StatusOK, w.Result().StatusCode)
	assert.Equal(t, "# metrics\n", w.Body.String())
}

func TestMetrics_CleansUpResultsFile(t *testing.T) {
	withTempOutputDirs(t)

	defer func(o scanner) { scanImpl = o }(scanImpl)
	scanImpl = func(_ context.Context, scanInfo *cautils.ScanInfo, _ []cautils.PolicyIdentifier, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
		resolved, _ := printer.ResolveOutputFile(printer.PrometheusFormat, scanInfo.Output, "")
		require.NoError(t, os.WriteFile(resolved, []byte("# metrics\n"), 0o600))
		return nil, nil
	}

	h := NewHTTPHandler(false)
	rq := httptest.NewRequest(http.MethodGet, "/v1/metrics", nil)
	w := httptest.NewRecorder()

	h.Metrics(w, rq)

	require.Equal(t, http.StatusOK, w.Result().StatusCode)
	entries, err := os.ReadDir(OutputDir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestMetrics_CleansUpResultsFileWithConfiguredFormat(t *testing.T) {
	withTempOutputDirs(t)
	t.Setenv("KS_FORMAT", "json")

	defer func(o scanner) { scanImpl = o }(scanImpl)
	scanImpl = func(_ context.Context, scanInfo *cautils.ScanInfo, _ []cautils.PolicyIdentifier, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
		resolved, _ := printer.ResolveOutputFile(scanInfo.Format, scanInfo.Output, "")
		require.NoError(t, os.WriteFile(resolved, []byte("{}"), 0o600))
		return nil, nil
	}

	h := NewHTTPHandler(false)
	rq := httptest.NewRequest(http.MethodGet, "/v1/metrics", nil)
	w := httptest.NewRecorder()

	h.Metrics(w, rq)

	entries, err := os.ReadDir(OutputDir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestMetrics_CleansUpResultsFileOnDisconnect(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		withTempOutputDirs(t)

		defer func(o scanner) { scanImpl = o }(scanImpl)
		scanCtxErr := make(chan error, 1)

		reqCtx, cancel := context.WithCancel(context.Background())
		handlerDone := make(chan struct{})
		scanImpl = func(ctx context.Context, scanInfo *cautils.ScanInfo, _ []cautils.PolicyIdentifier, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
			cancel()      // simulate the scrape connection going away mid-scan
			<-handlerDone // wait for the handler to return on the disconnect path before writing
			scanCtxErr <- ctx.Err()
			resolved, _ := printer.ResolveOutputFile(printer.PrometheusFormat, scanInfo.Output, "")
			require.NoError(t, os.WriteFile(resolved, []byte("# metrics\n"), 0o600))
			return nil, nil
		}

		h := NewHTTPHandler(false)
		rq := httptest.NewRequest(http.MethodGet, "/v1/metrics", nil).WithContext(reqCtx)
		w := httptest.NewRecorder()

		go func() {
			h.Metrics(w, rq)
			close(handlerDone)
		}()

		select {
		case err := <-scanCtxErr:
			assert.ErrorIs(t, err, context.Canceled, "scan context must be cancelled when the request context is")
		case <-time.After(5 * time.Second):
			t.Fatal("scan was not invoked")
		}

		select {
		case <-handlerDone:
		case <-time.After(5 * time.Second):
			t.Fatal("handler did not complete")
		}

		assert.NoError(t, h.Shutdown(context.Background(), time.Second))
		synctest.Wait() // join the disconnect cleanup goroutine before asserting

		entries, err := os.ReadDir(OutputDir)
		require.NoError(t, err)
		assert.Empty(t, entries)
	})
}

func TestMetrics_InvalidSkipPersistenceQueryParam(t *testing.T) {
	defer func(o scanner) { scanImpl = o }(scanImpl)
	scanCalled := make(chan struct{}, 1)
	scanImpl = func(context.Context, *cautils.ScanInfo, []cautils.PolicyIdentifier, string, bool) (*reporthandlingv2.PostureReport, error) {
		scanCalled <- struct{}{}
		return nil, nil
	}

	h := NewHTTPHandler(false)
	rq := httptest.NewRequest(http.MethodGet, "/v1/metrics?skipPersistence=definitely", nil)
	w := httptest.NewRecorder()

	h.Metrics(w, rq)

	require.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
	select {
	case <-scanCalled:
		t.Fatal("scan should not be invoked when query parsing fails")
	default:
	}
}

func TestMetrics_NonGetMethodReturns405WithoutScanning(t *testing.T) {
	defer func(o scanner) { scanImpl = o }(scanImpl)
	scanCalled := make(chan struct{}, 1)
	scanImpl = func(context.Context, *cautils.ScanInfo, []cautils.PolicyIdentifier, string, bool) (*reporthandlingv2.PostureReport, error) {
		scanCalled <- struct{}{}
		return nil, nil
	}

	h := NewHTTPHandler(false)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			rq := httptest.NewRequest(method, "/v1/metrics", nil)
			w := httptest.NewRecorder()

			h.Metrics(w, rq)

			require.Equal(t, http.StatusMethodNotAllowed, w.Result().StatusCode)
			assert.Equal(t, http.MethodGet, w.Result().Header.Get("Allow"), "405 response must advertise the allowed method")
			select {
			case <-scanCalled:
				t.Fatal("scan should not be invoked for non-GET metrics requests")
			default:
			}
		})
	}
}

// blockFirstScan makes the first scan block until release is called; every
// scan writes a Prometheus results file so metrics requests can complete.
func blockFirstScan(t *testing.T) (started <-chan struct{}, release func()) {
	t.Helper()
	startedCh := make(chan struct{})
	releaseCh := make(chan struct{})
	var startOnce, releaseOnce sync.Once
	original := scanImpl
	scanImpl = func(_ context.Context, scanInfo *cautils.ScanInfo, _ []cautils.PolicyIdentifier, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
		first := false
		startOnce.Do(func() { first = true; close(startedCh) })
		if first {
			<-releaseCh
		}
		if scanInfo.Output != "" {
			resolved, _ := printer.ResolveOutputFile(printer.PrometheusFormat, scanInfo.Output, "")
			_ = os.WriteFile(resolved, []byte("# metrics\n"), 0o600)
		}
		return nil, nil
	}
	t.Cleanup(func() { scanImpl = original })
	return startedCh, func() { releaseOnce.Do(func() { close(releaseCh) }) }
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal(what)
	}
}

func performMetricsRequest(handler *HTTPHandler) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.Metrics(recorder, httptest.NewRequest(http.MethodGet, "/v1/metrics", nil))
	return recorder
}

// TestMetricsScansAreSingleFlight checks that unauthenticated scrapes hold at
// most one scan admission at a time, so they cannot crowd out POST /v1/scan.
func TestMetricsScansAreSingleFlight(t *testing.T) {
	withTempOutputDirs(t)
	started, release := blockFirstScan(t)
	handler := newHTTPHandler(false, 2, defaultMaxScanRequestBodyBytes)
	t.Cleanup(func() {
		release()
		require.Eventually(t, func() bool { return handlerStateIsDrained(handler) }, time.Second, 10*time.Millisecond)
	})

	firstDone := make(chan struct{})
	var first *httptest.ResponseRecorder
	go func() {
		first = performMetricsRequest(handler)
		close(firstDone)
	}()
	waitClosed(t, started, "first metrics scan did not start")

	// Without the guard this scrape would queue and block on the first one.
	secondDone := make(chan struct{})
	var second *httptest.ResponseRecorder
	go func() {
		second = performMetricsRequest(handler)
		close(secondDone)
	}()
	waitClosed(t, secondDone, "a concurrent scrape must be rejected, not queued")
	assert.Equal(t, http.StatusTooManyRequests, second.Code)
	assert.Equal(t, "1", second.Header().Get("Retry-After"))
	response := decodeScanResponse(t, second)
	assert.Equal(t, utilsapisv1.ErrorScanResponseType, response.Type)
	assert.Contains(t, fmt.Sprint(response.Response), "a metrics scan is already running")
	assert.Zero(t, len(handler.scanRequestChan), "a rejected scrape must not take a queue slot")
	assert.Equal(t, 1, handler.state.len(), "a rejected scrape must not be registered")

	// An authenticated scan is still admitted while the metrics scan runs.
	userScan := performAsyncScanRequest(t, handler, `{"account":"test"}`)
	assert.Equal(t, http.StatusOK, userScan.Code)
	assert.Equal(t, 1, len(handler.scanRequestChan), "the user scan should wait in the user queue")

	release()
	waitClosed(t, firstDone, "first metrics request did not complete")
	assert.Equal(t, http.StatusOK, first.Code)

	third := performMetricsRequest(handler)
	assert.Equal(t, http.StatusOK, third.Code, "a scrape after the in-flight one finished must be admitted")
	assert.Equal(t, "# metrics\n", third.Body.String())
}

// TestMetricsQueueFullReleasesSlot checks that a scrape rejected by a full
// metrics lane gets the queue-full error and does not keep the metrics slot.
func TestMetricsQueueFullReleasesSlot(t *testing.T) {
	withTempOutputDirs(t)
	// No worker: the pre-filled metrics lane stays full.
	handler := &HTTPHandler{
		state:              newServerState(),
		scanRequestChan:    make(chan *scanRequestParams, 1),
		metricsRequestChan: make(chan *scanRequestParams, 1),
		metricsScanSlot:    make(chan struct{}, 1),
	}
	handler.metricsRequestChan <- &scanRequestParams{}

	rejected := performMetricsRequest(handler)
	assert.Equal(t, http.StatusTooManyRequests, rejected.Code)
	assert.Equal(t, "1", rejected.Header().Get("Retry-After"))
	assert.Contains(t, fmt.Sprint(decodeScanResponse(t, rejected).Response), "scan queue is full")
	assert.Zero(t, len(handler.metricsScanSlot), "a scrape rejected by the queue must release the metrics slot")
	assert.Zero(t, len(handler.scanRequestChan), "a scrape must never enter the user queue")
	assert.Zero(t, handler.state.len())
}

// With KS_SCAN_QUEUE_CAPACITY=1 and a user scan running, a pending scrape
// must not take the only user queue slot.
func TestPendingMetricsScanDoesNotBlockUserScan(t *testing.T) {
	withTempOutputDirs(t)
	started, release := blockFirstScan(t)
	handler := newHTTPHandler(false, 1, defaultMaxScanRequestBodyBytes)
	t.Cleanup(func() {
		release()
		require.Eventually(t, func() bool { return handlerStateIsDrained(handler) }, time.Second, 10*time.Millisecond)
	})

	body := `{"account":"test"}`
	require.Equal(t, http.StatusOK, performAsyncScanRequest(t, handler, body).Code)
	waitClosed(t, started, "first scan did not start")

	metricsDone := make(chan struct{})
	var metrics *httptest.ResponseRecorder
	go func() {
		metrics = performMetricsRequest(handler)
		close(metricsDone)
	}()
	require.Eventually(t, func() bool { return len(handler.metricsRequestChan) == 1 }, 2*time.Second, 5*time.Millisecond,
		"the scrape should be pending in the metrics lane")

	userScan := performAsyncScanRequest(t, handler, body)
	assert.Equal(t, http.StatusOK, userScan.Code, "a pending scrape must not fill the user queue")
	assert.Equal(t, 1, len(handler.scanRequestChan))

	release()
	waitClosed(t, metricsDone, "metrics request did not complete")
	assert.Equal(t, http.StatusOK, metrics.Code)
}

// With KS_SCAN_QUEUE_CAPACITY=1, a running and a pending user scan must not
// keep a scrape from being admitted.
func TestPendingUserScanDoesNotBlockMetricsScan(t *testing.T) {
	withTempOutputDirs(t)
	started, release := blockFirstScan(t)
	handler := newHTTPHandler(false, 1, defaultMaxScanRequestBodyBytes)
	t.Cleanup(func() {
		release()
		require.Eventually(t, func() bool { return handlerStateIsDrained(handler) }, time.Second, 10*time.Millisecond)
	})

	body := `{"account":"test"}`
	require.Equal(t, http.StatusOK, performAsyncScanRequest(t, handler, body).Code)
	waitClosed(t, started, "first scan did not start")
	require.Equal(t, http.StatusOK, performAsyncScanRequest(t, handler, body).Code)
	require.Equal(t, 1, len(handler.scanRequestChan))

	metricsDone := make(chan struct{})
	var metrics *httptest.ResponseRecorder
	go func() {
		metrics = performMetricsRequest(handler)
		close(metricsDone)
	}()
	require.Eventually(t, func() bool { return len(handler.metricsRequestChan) == 1 }, 2*time.Second, 5*time.Millisecond,
		"the scrape should be admitted while the user queue is full")

	release()
	waitClosed(t, metricsDone, "metrics request did not complete")
	assert.Equal(t, http.StatusOK, metrics.Code)
}

func TestSplitAndTrim(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		sep      string
		expected []string
	}{
		{
			name:     "comma-separated with spaces",
			input:    "nsa, mitre, cis-v1.10.0",
			sep:      ",",
			expected: []string{"nsa", "mitre", "cis-v1.10.0"},
		},
		{
			name:     "no spaces",
			input:    "nsa,mitre,cis-v1.10.0",
			sep:      ",",
			expected: []string{"nsa", "mitre", "cis-v1.10.0"},
		},
		{
			name:     "single item",
			input:    "nsa",
			sep:      ",",
			expected: []string{"nsa"},
		},
		{
			name:     "empty string",
			input:    "",
			sep:      ",",
			expected: []string{},
		},
		{
			name:     "whitespace only",
			input:    "  ,  ,  ",
			sep:      ",",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitAndTrim(tt.input, tt.sep)
			assert.Equal(t, tt.expected, result)
		})
	}
}
