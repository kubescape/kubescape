package v1

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
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

// TestMetrics_ScanContextDecoupledFromRequest ensures the metrics scan is not
// aborted when the scrape request context is cancelled (e.g. a Prometheus
// scrape timeout): the scan must keep running to completion.
func TestMetrics_ScanContextDecoupledFromRequest(t *testing.T) {
	defer func(o scanner) { scanImpl = o }(scanImpl)
	scanCtxErr := make(chan error, 1)

	reqCtx, cancel := context.WithCancel(context.Background())
	scanImpl = func(ctx context.Context, _ *cautils.ScanInfo, _ []cautils.PolicyIdentifier, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
		cancel() // simulate the scrape connection going away mid-scan
		scanCtxErr <- ctx.Err()
		return nil, nil
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
		assert.NoError(t, err, "scan context must not be cancelled when the request context is")
	case <-time.After(5 * time.Second):
		t.Fatal("scan was not invoked")
	}

	select {
	case <-handlerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not complete")
	}
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
				require.NoError(t, os.WriteFile(scanInfo.Output, []byte("# metrics\n"), 0o600))
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

func TestMetricsQueueRejectsRequestsWhenCapacityIsExhausted(t *testing.T) {
	withTempOutputDirs(t)

	originalScanImpl := scanImpl
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var releaseOnce sync.Once
	releaseScans := func() { releaseOnce.Do(func() { close(release) }) }
	scanImpl = func(_ context.Context, scanInfo *cautils.ScanInfo, _ []cautils.PolicyIdentifier, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
		once.Do(func() { close(started) })
		<-release
		require.NoError(t, os.WriteFile(scanInfo.Output, []byte("# metrics\n"), 0o600))
		return nil, nil
	}
	handler := newHTTPHandler(false, 1, defaultMaxScanRequestBodyBytes)
	t.Cleanup(func() {
		releaseScans()
		require.Eventually(t, func() bool { return handlerStateIsDrained(handler) }, time.Second, 10*time.Millisecond)
		scanImpl = originalScanImpl
	})

	firstDone := make(chan struct{})
	go func() {
		recorder := httptest.NewRecorder()
		handler.Metrics(recorder, httptest.NewRequest(http.MethodGet, "/v1/metrics", nil))
		close(firstDone)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first metrics scan did not start")
	}

	secondQueued := make(chan struct{})
	secondDone := make(chan struct{})
	go func() {
		recorder := httptest.NewRecorder()
		handler.Metrics(recorder, httptest.NewRequest(http.MethodGet, "/v1/metrics", nil))
		close(secondDone)
	}()
	require.Eventually(t, func() bool {
		if len(handler.scanRequestChan) == 1 {
			close(secondQueued)
			return true
		}
		return false
	}, time.Second, 10*time.Millisecond)

	rejected := httptest.NewRecorder()
	handler.Metrics(rejected, httptest.NewRequest(http.MethodGet, "/v1/metrics", nil))

	assert.Equal(t, http.StatusTooManyRequests, rejected.Code)
	assert.Equal(t, "1", rejected.Header().Get("Retry-After"))
	response := decodeScanResponse(t, rejected)
	assert.Equal(t, utilsapisv1.ErrorScanResponseType, response.Type)
	assert.Contains(t, fmt.Sprint(response.Response), "scan queue is full")

	releaseScans()
	select {
	case <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("first metrics request did not complete")
	}
	select {
	case <-secondQueued:
	default:
		t.Fatal("second metrics request was not queued")
	}
	select {
	case <-secondDone:
	case <-time.After(2 * time.Second):
		t.Fatal("second metrics request did not complete")
	}
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
