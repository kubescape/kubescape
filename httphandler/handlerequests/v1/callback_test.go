package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/core/cautils"
	utilsapisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubResolver struct {
	ips []net.IPAddr
	err error
}

func (s stubResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return s.ips, s.err
}

// countingCallbackReceiver starts a server that records every delivered
// payload (unbounded), so a duplicate delivery can never be silently dropped
// the way a one-slot channel could. No t.Parallel alongside scanImpl stubs.
func countingCallbackReceiver(t *testing.T) (string, <-chan scanCallbackPayload, *atomic.Int32) {
	t.Helper()
	var count atomic.Int32
	received := make(chan scanCallbackPayload, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p scanCallbackPayload
		_ = json.NewDecoder(r.Body).Decode(&p)
		count.Add(1)
		select {
		case received <- p:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, received, &count
}
func callbackReceiver(t *testing.T) (string, <-chan scanCallbackPayload) {
	t.Helper()
	received := make(chan scanCallbackPayload, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p scanCallbackPayload
		_ = json.NewDecoder(r.Body).Decode(&p)
		select {
		case received <- p:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, received
}

func TestExecuteScan_CallbackOnSuccess(t *testing.T) {
	// httptest listens on loopback, so the allowlist must explicitly permit it.
	t.Setenv(callbackAllowlistEnv, "127.0.0.1/32")
	defer func(o scanner) { scanImpl = o }(scanImpl)
	scanImpl = func(context.Context, *cautils.ScanInfo, []cautils.PolicyIdentifier, string, bool) (*reporthandlingv2.PostureReport, error) {
		return nil, nil
	}

	url, received := callbackReceiver(t)
	h := NewHTTPHandler(false)
	h.executeScan(&scanRequestParams{
		scanInfo:        &cautils.ScanInfo{},
		scanQueryParams: &ScanQueryParams{},
		scanID:          "scan-success",
		ctx:             context.Background(),
		callbackURL:     url,
	})

	select {
	case p := <-received:
		assert.Equal(t, "scan-success", p.ID)
		assert.Equal(t, callbackStatusCompleted, p.Status)
		assert.Empty(t, p.Error)
	case <-time.After(5 * time.Second):
		t.Fatal("callback was not delivered within 5s")
	}
}

func TestExecuteScan_CallbackOnFailure(t *testing.T) {
	t.Setenv(callbackAllowlistEnv, "127.0.0.1/32")
	defer func(o scanner) { scanImpl = o }(scanImpl)
	scanImpl = func(context.Context, *cautils.ScanInfo, []cautils.PolicyIdentifier, string, bool) (*reporthandlingv2.PostureReport, error) {
		return nil, fmt.Errorf("collection boom")
	}

	url, received := callbackReceiver(t)
	h := NewHTTPHandler(false)
	h.executeScan(&scanRequestParams{
		scanInfo:        &cautils.ScanInfo{},
		scanQueryParams: &ScanQueryParams{},
		scanID:          "scan-failed",
		ctx:             context.Background(),
		callbackURL:     url,
	})

	select {
	case p := <-received:
		assert.Equal(t, "scan-failed", p.ID)
		assert.Equal(t, callbackStatusFailed, p.Status)
		assert.Equal(t, "scan failed", p.Error)
		assert.NotContains(t, p.Error, "collection boom")
	case <-time.After(5 * time.Second):
		t.Fatal("callback was not delivered within 5s")
	}
}

func TestValidateCallbackURL_DisabledByDefault(t *testing.T) {
	t.Setenv(callbackAllowlistEnv, "")
	t.Setenv(callbackEnabledEnv, "")
	_, err := validateCallbackURL("http://example.com/hook")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disabled")
}

func TestValidateCallbackURL_Rejections(t *testing.T) {
	t.Setenv(callbackEnabledEnv, "true")
	for _, tc := range []struct {
		name, url, contains string
	}{
		{"userinfo", "http://user:pass@example.com/hook", "userinfo"},
		{"scheme", "ftp://example.com/hook", "scheme"},
		{"no host", "http:///hook", "host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateCallbackURL(tc.url)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.contains)
		})
	}
}

func TestPostScanCallback_SSRFBlockedByDefault(t *testing.T) {
	t.Setenv(callbackAllowlistEnv, "")
	t.Setenv(callbackEnabledEnv, "true")
	for _, tc := range []struct {
		name, url string
	}{
		{"loopback", "http://127.0.0.1:1/hook"},
		{"link-local-metadata", "http://169.254.169.254/latest/meta-data"},
		{"rfc1918-10", "http://10.0.0.5/hook"},
		{"rfc1918-192", "http://192.168.1.10/hook"},
		{"cgnat", "http://100.64.0.1/hook"},
		{"this-host", "http://0.1.2.3/hook"},
		{"broadcast", "http://255.255.255.255/hook"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := postScanCallback(context.Background(), tc.url, scanCallbackPayload{ID: "x"})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "disallowed")
		})
	}
}

func TestPostScanCallback_NoRetryOn4xx(t *testing.T) {
	t.Setenv(callbackAllowlistEnv, "127.0.0.1/32")
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	err := postScanCallback(context.Background(), srv.URL, scanCallbackPayload{ID: "x"})
	require.Error(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "4xx must not be retried")
}

func TestPostScanCallback_DNSRebindToInternalIsRejected(t *testing.T) {
	t.Setenv(callbackAllowlistEnv, "")
	t.Setenv(callbackEnabledEnv, "true")
	defer func(o ipResolver) { callbackResolver = o }(callbackResolver)
	// A benign-looking host that resolves to the cloud metadata address: because
	// screening runs on the resolved IP (and the dial is pinned to it), the
	// rebind cannot smuggle an internal target past the literal-IP checks.
	callbackResolver = stubResolver{ips: []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}}

	err := postScanCallback(context.Background(), "http://benign.example.com/hook", scanCallbackPayload{ID: "x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disallowed")
}

func TestScreenCallbackHost_PinsResolvedIP(t *testing.T) {
	t.Setenv(callbackAllowlistEnv, "")
	defer func(o ipResolver) { callbackResolver = o }(callbackResolver)
	callbackResolver = stubResolver{ips: []net.IPAddr{{IP: net.ParseIP("203.0.113.7")}}}

	ip, err := screenCallbackHost(context.Background(), "public.example.com")
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.7", ip.String())
}

// TestExecuteScan_CallbackOnPanic pins the #3825 contract: a panicking scan
// with a callbackURL still delivers exactly one generic failed signal, and
// waiters still get their error response. No t.Parallel: global scanImpl stub.
func TestExecuteScan_CallbackOnPanic(t *testing.T) {
	t.Setenv(callbackAllowlistEnv, "127.0.0.1/32")
	withTempOutputDirs(t)
	defer func(o scanner) { scanImpl = o }(scanImpl)
	scanImpl = func(context.Context, *cautils.ScanInfo, []cautils.PolicyIdentifier, string, bool) (*reporthandlingv2.PostureReport, error) {
		panic("boom")
	}

	url, received, deliveries := countingCallbackReceiver(t)
	h := NewHTTPHandler(false)
	resp := make(chan *utilsmetav1.Response, 1)
	h.executeScan(&scanRequestParams{
		scanInfo:        &cautils.ScanInfo{},
		scanQueryParams: &ScanQueryParams{ReturnResults: true},
		scanID:          "scan-panicked",
		ctx:             context.Background(),
		resp:            resp,
		callbackURL:     url,
	})

	select {
	case r := <-resp:
		assert.Equal(t, "scan-panicked", r.ID)
		assert.Equal(t, utilsapisv1.ErrorScanResponseType, r.Type)
	case <-time.After(5 * time.Second):
		t.Fatal("panic response was not fed within 5s")
	}

	select {
	case p := <-received:
		assert.Equal(t, "scan-panicked", p.ID)
		assert.Equal(t, callbackStatusFailed, p.Status)
		assert.Equal(t, callbackErrPanicked, p.Error)
		assert.NotContains(t, p.Error, "boom")
	case <-time.After(5 * time.Second):
		t.Fatal("panic callback was not delivered within 5s")
	}

	select {
	case p := <-received:
		t.Fatalf("duplicate panic callback delivered: %+v", p)
	case <-time.After(500 * time.Millisecond):
	}
	assert.Equal(t, int32(1), deliveries.Load(), "panic path must deliver exactly one callback")
}

// TestExecuteScan_PanicWithoutCallbackURL ensures a panicking scan without a
// webhook still releases cleanly and feeds waiters.
func TestExecuteScan_PanicWithoutCallbackURL(t *testing.T) {
	withTempOutputDirs(t)
	defer func(o scanner) { scanImpl = o }(scanImpl)
	scanImpl = func(context.Context, *cautils.ScanInfo, []cautils.PolicyIdentifier, string, bool) (*reporthandlingv2.PostureReport, error) {
		panic("boom")
	}

	h := NewHTTPHandler(false)
	resp := make(chan *utilsmetav1.Response, 1)
	h.executeScan(&scanRequestParams{
		scanInfo:        &cautils.ScanInfo{},
		scanQueryParams: &ScanQueryParams{ReturnResults: true},
		scanID:          "scan-panicked-nocb",
		ctx:             context.Background(),
		resp:            resp,
	})

	select {
	case r := <-resp:
		assert.Equal(t, "scan-panicked-nocb", r.ID)
		assert.Equal(t, utilsapisv1.ErrorScanResponseType, r.Type)
	case <-time.After(5 * time.Second):
		t.Fatal("panic response was not fed within 5s")
	}
	assert.False(t, h.state.isBusy("scan-panicked-nocb"))
}

// TestExecuteScan_PanicNilParams guards the recover block itself: nil
// scanQueryParams/ctx must not cause a secondary panic that kills the worker.
func TestExecuteScan_PanicNilParams(t *testing.T) {
	t.Setenv(callbackAllowlistEnv, "127.0.0.1/32")
	withTempOutputDirs(t)
	defer func(o scanner) { scanImpl = o }(scanImpl)
	scanImpl = func(context.Context, *cautils.ScanInfo, []cautils.PolicyIdentifier, string, bool) (*reporthandlingv2.PostureReport, error) {
		panic("boom")
	}

	url, received := callbackReceiver(t)
	h := NewHTTPHandler(false)
	h.executeScan(&scanRequestParams{
		scanID:      "scan-panicked-nil",
		callbackURL: url,
	})

	select {
	case p := <-received:
		assert.Equal(t, "scan-panicked-nil", p.ID)
		assert.Equal(t, callbackStatusFailed, p.Status)
	case <-time.After(5 * time.Second):
		t.Fatal("panic callback was not delivered within 5s")
	}
}

// TestExecuteScan_PanicCleansPartialResults mirrors the cancel invariant: a
// panicking scan must not leave a truncated OutputDir artifact servable as
// valid, while the error signal lands in FailedOutputDir.
func TestExecuteScan_PanicCleansPartialResults(t *testing.T) {
	withTempOutputDirs(t)
	defer func(o scanner) { scanImpl = o }(scanImpl)
	scanImpl = func(context.Context, *cautils.ScanInfo, []cautils.PolicyIdentifier, string, bool) (*reporthandlingv2.PostureReport, error) {
		panic("boom")
	}

	scanID := "123e4567-e89b-12d3-a456-426614174000"
	require.NoError(t, os.WriteFile(filepath.Join(OutputDir, scanID), []byte("partial"), 0o600))

	h := NewHTTPHandler(false)
	h.executeScan(&scanRequestParams{
		scanInfo:        &cautils.ScanInfo{},
		scanQueryParams: &ScanQueryParams{},
		scanID:          scanID,
		ctx:             context.Background(),
	})

	_, err := os.Stat(filepath.Join(OutputDir, scanID))
	assert.True(t, os.IsNotExist(err), "partial results artifact must be removed on panic")
	_, err = os.Stat(filepath.Join(FailedOutputDir, scanID))
	assert.NoError(t, err, "panic error signal must be persisted")
}
