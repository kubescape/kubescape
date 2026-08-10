package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v3/core/cautils"
	utilsapisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func performAsyncScanRequest(t *testing.T, handler *HTTPHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/scan", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	handler.Scan(recorder, req)
	return recorder
}

func decodeScanResponse(t *testing.T, recorder *httptest.ResponseRecorder) utilsmetav1.Response {
	t.Helper()
	var response utilsmetav1.Response
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	return response
}

func handlerStateIsDrained(handler *HTTPHandler) bool {
	return handler.state.len() == 0 && len(handler.scanRequestChan) == 0
}

func TestScanQueueRejectsRequestsWhenCapacityIsExhausted(t *testing.T) {
	originalScanImpl := scanImpl
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var releaseOnce sync.Once
	releaseScans := func() { releaseOnce.Do(func() { close(release) }) }
	scanImpl = func(context.Context, *cautils.ScanInfo, []cautils.PolicyIdentifier, string, bool) (*reporthandlingv2.PostureReport, error) {
		once.Do(func() { close(started) })
		<-release
		return nil, nil
	}
	handler := newHTTPHandler(false, 1, defaultMaxScanRequestBodyBytes)
	t.Cleanup(func() {
		releaseScans()
		require.Eventually(t, func() bool { return handlerStateIsDrained(handler) }, time.Second, 10*time.Millisecond)
		scanImpl = originalScanImpl
	})

	body := `{"account":"test"}`

	first := performAsyncScanRequest(t, handler, body)
	require.Equal(t, http.StatusOK, first.Code)
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first scan did not start")
	}

	second := performAsyncScanRequest(t, handler, body)
	require.Equal(t, http.StatusOK, second.Code)
	assert.Equal(t, 1, len(handler.scanRequestChan), "second scan should occupy the only queue slot")
	assert.Equal(t, 2, handler.state.len(), "active and queued scans should be tracked")

	rejected := performAsyncScanRequest(t, handler, body)
	assert.Equal(t, http.StatusTooManyRequests, rejected.Code)
	assert.Equal(t, "1", rejected.Header().Get("Retry-After"))
	response := decodeScanResponse(t, rejected)
	assert.Equal(t, utilsapisv1.ErrorScanResponseType, response.Type)
	assert.Contains(t, fmt.Sprint(response.Response), "scan queue is full")
	assert.Equal(t, 2, handler.state.len(), "a rejected request must not remain busy")

	releaseScans()
	require.Eventually(t, func() bool { return handlerStateIsDrained(handler) }, time.Second, 10*time.Millisecond)
}

func TestScanQueuePreservesAdmissionOrder(t *testing.T) {
	originalScanImpl := scanImpl
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseScans := func() { releaseOnce.Do(func() { close(release) }) }
	completed := make(chan string, 3)
	var callCount atomic.Int32
	scanImpl = func(_ context.Context, _ *cautils.ScanInfo, _ []cautils.PolicyIdentifier, scanID string, _ bool) (*reporthandlingv2.PostureReport, error) {
		if callCount.Add(1) == 1 {
			close(started)
			<-release
		}
		completed <- scanID
		return nil, nil
	}

	handler := newHTTPHandler(false, 2, defaultMaxScanRequestBodyBytes)
	t.Cleanup(func() {
		releaseScans()
		require.Eventually(t, func() bool { return handlerStateIsDrained(handler) }, time.Second, 10*time.Millisecond)
		scanImpl = originalScanImpl
	})
	body := `{"account":"test"}`
	recorders := []*httptest.ResponseRecorder{
		performAsyncScanRequest(t, handler, body),
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first scan did not start")
	}
	recorders = append(recorders,
		performAsyncScanRequest(t, handler, body),
		performAsyncScanRequest(t, handler, body),
	)

	want := make([]string, 0, len(recorders))
	for _, recorder := range recorders {
		require.Equal(t, http.StatusOK, recorder.Code)
		want = append(want, decodeScanResponse(t, recorder).ID)
	}
	releaseScans()

	got := make([]string, 0, len(want))
	for range want {
		select {
		case id := <-completed:
			got = append(got, id)
		case <-time.After(2 * time.Second):
			t.Fatal("queued scan did not complete")
		}
	}
	assert.Equal(t, want, got)
	require.Eventually(t, func() bool { return handlerStateIsDrained(handler) }, time.Second, 10*time.Millisecond)
}

func TestScanRejectsOversizedRequestBodyBeforeAdmission(t *testing.T) {
	defer func(original scanner) { scanImpl = original }(scanImpl)
	var calls atomic.Int32
	scanImpl = func(context.Context, *cautils.ScanInfo, []cautils.PolicyIdentifier, string, bool) (*reporthandlingv2.PostureReport, error) {
		calls.Add(1)
		return nil, nil
	}

	const limit = int64(64)
	handler := newHTTPHandler(false, 1, limit)
	body := `{"account":"` + strings.Repeat("x", 128) + `"}`

	recorder := performAsyncScanRequest(t, handler, body)

	assert.Equal(t, http.StatusRequestEntityTooLarge, recorder.Code)
	response := decodeScanResponse(t, recorder)
	assert.Equal(t, utilsapisv1.ErrorScanResponseType, response.Type)
	assert.Contains(t, fmt.Sprint(response.Response), "64 byte limit")
	assert.Zero(t, calls.Load())
	assert.Zero(t, handler.state.len())
	assert.Zero(t, len(handler.scanRequestChan))
}

func TestConfiguredPositiveInt(t *testing.T) {
	const name = "TEST_KUBESCAPE_POSITIVE_INT"

	t.Run("uses configured value", func(t *testing.T) {
		t.Setenv(name, "7")
		assert.Equal(t, 7, configuredPositiveInt(name, 3))
	})

	t.Run("rejects zero", func(t *testing.T) {
		t.Setenv(name, "0")
		assert.Equal(t, 3, configuredPositiveInt(name, 3))
	})

	t.Run("rejects malformed value", func(t *testing.T) {
		t.Setenv(name, "many")
		assert.Equal(t, 3, configuredPositiveInt(name, 3))
	})
}
