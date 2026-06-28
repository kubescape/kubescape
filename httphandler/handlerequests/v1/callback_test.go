package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v3/core/cautils"
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

// callbackReceiver starts a server that captures the first delivered payload.
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
	scanImpl = func(context.Context, *cautils.ScanInfo, string, bool) (*reporthandlingv2.PostureReport, error) {
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
	scanImpl = func(context.Context, *cautils.ScanInfo, string, bool) (*reporthandlingv2.PostureReport, error) {
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
