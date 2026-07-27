package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	"github.com/kubescape/kubescape/v3/httphandler/config"
)

// validServicesV3JSON is a minimal well-formed service-discovery v3 payload.
const validServicesV3JSON = `{"version":"v3","response":{"api-server":"https://api.test.io","event-receiver-http":"https://report.test.io"}}`

// TestInitializeSaaSEnv_fileSuccess verifies that a valid services.json causes
// initializeSaaSEnv to complete without crashing.
func TestInitializeSaaSEnv_fileSuccess(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "services*.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(validServicesV3JSON); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()

	t.Setenv("KS_SERVICE_DISCOVERY_FILE_PATH", f.Name())

	initializeSaaSEnv()
}

// TestInitializeSaaSEnv_apiSuccess verifies that a reachable API endpoint causes
// initializeSaaSEnv to complete without crashing.
func TestInitializeSaaSEnv_apiSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/servicediscovery" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(validServicesV3JSON))
	}))
	t.Cleanup(srv.Close)

	// Ensure no file is found, and that KS_SERVICE_DISCOVERY_FILE_PATH isn't
	// explicitly set (which would now short-circuit before the API path),
	// so the API path is genuinely exercised.
	origDefaultPath := defaultServiceDiscoveryPath
	defaultServiceDiscoveryPath = filepath.Join(t.TempDir(), "no-services.json")
	t.Cleanup(func() { defaultServiceDiscoveryPath = origDefaultPath })
	t.Setenv("KS_SERVICE_DISCOVERY_FILE_PATH", "")
	// srv.URL is "http://127.0.0.1:PORT" — ParseHost preserves the http scheme.
	t.Setenv("API_URL", srv.URL)

	origTimeout := serviceDiscoveryTimeout
	serviceDiscoveryTimeout = 5 * time.Second
	t.Cleanup(func() { serviceDiscoveryTimeout = origTimeout })

	initializeSaaSEnv()
}

// TestInitializeSaaSEnv_networkFailure verifies that a transient network error
// causes initializeSaaSEnv to log a warning and return instead of crashing.
func TestInitializeSaaSEnv_networkFailure(t *testing.T) {
	// Ensure no file is found, and that KS_SERVICE_DISCOVERY_FILE_PATH isn't
	// explicitly set (which would now short-circuit before the API path),
	// so the API path is genuinely exercised.
	origDefaultPath := defaultServiceDiscoveryPath
	defaultServiceDiscoveryPath = filepath.Join(t.TempDir(), "no-services.json")
	t.Cleanup(func() { defaultServiceDiscoveryPath = origDefaultPath })
	t.Setenv("KS_SERVICE_DISCOVERY_FILE_PATH", "")
	// Port 1 refuses connections immediately on loopback.
	t.Setenv("API_URL", "http://127.0.0.1:1")

	origTimeout := serviceDiscoveryTimeout
	serviceDiscoveryTimeout = 50 * time.Millisecond
	t.Cleanup(func() { serviceDiscoveryTimeout = origTimeout })

	initializeSaaSEnv() // must log a warning and return, not call Fatal/os.Exit
}

// TestInitializeSaaSEnv_noBackendConfigured verifies that with no service-discovery
// file, no API_URL, and no account/accessKey, initializeSaaSEnv skips SaaS wiring
// entirely (no network call, no cloud connector set) - see
// https://github.com/kubescape/kubescape/issues/2555.
func TestInitializeSaaSEnv_noBackendConfigured(t *testing.T) {
	origAccount, origAccessKey := config.GetAccount(), config.GetAccessKey()
	config.SetAccount("")
	config.SetAccessKey("")
	t.Cleanup(func() {
		config.SetAccount(origAccount)
		config.SetAccessKey(origAccessKey)
	})

	origConnector := getter.GetKSCloudAPIConnector()
	getter.SetKSCloudAPIConnector(nil)
	t.Cleanup(func() { getter.SetKSCloudAPIConnector(origConnector) })

	// No explicit KS_SERVICE_DISCOVERY_FILE_PATH (an explicit-but-missing
	// path is a different case - see TestInitializeSaaSEnv_explicitServiceDiscoveryFileMissing).
	origDefaultPath := defaultServiceDiscoveryPath
	defaultServiceDiscoveryPath = filepath.Join(t.TempDir(), "no-services.json")
	t.Cleanup(func() { defaultServiceDiscoveryPath = origDefaultPath })
	t.Setenv("KS_SERVICE_DISCOVERY_FILE_PATH", "")
	t.Setenv("API_URL", "")

	initializeSaaSEnv()

	conn := getter.GetKSCloudAPIConnector()
	if conn.GetCloudAPIURL() != "" || conn.GetCloudReportURL() != "" {
		t.Fatalf("expected no cloud connector URLs to be set when no backend is configured, got apiURL=%q reportURL=%q", conn.GetCloudAPIURL(), conn.GetCloudReportURL())
	}
}

// TestInitializeSaaSEnv_explicitServiceDiscoveryFileMissing verifies that an
// explicitly configured but missing KS_SERVICE_DISCOVERY_FILE_PATH is treated
// as a configuration problem (skip + warn) rather than silently falling back
// to network-based discovery, even when API_URL is also set.
func TestInitializeSaaSEnv_explicitServiceDiscoveryFileMissing(t *testing.T) {
	origAccount, origAccessKey := config.GetAccount(), config.GetAccessKey()
	config.SetAccount("")
	config.SetAccessKey("")
	t.Cleanup(func() {
		config.SetAccount(origAccount)
		config.SetAccessKey(origAccessKey)
	})

	origConnector := getter.GetKSCloudAPIConnector()
	getter.SetKSCloudAPIConnector(nil)
	t.Cleanup(func() { getter.SetKSCloudAPIConnector(origConnector) })

	t.Setenv("KS_SERVICE_DISCOVERY_FILE_PATH", filepath.Join(t.TempDir(), "missing-services.json"))
	// Port 1 refuses connections immediately - if the code fell through to the
	// network path despite the explicit file being missing, this would fail
	// fast rather than silently succeed, making a wiring regression obvious.
	t.Setenv("API_URL", "http://127.0.0.1:1")

	initializeSaaSEnv()

	conn := getter.GetKSCloudAPIConnector()
	if conn.GetCloudAPIURL() != "" || conn.GetCloudReportURL() != "" {
		t.Fatalf("expected no cloud connector URLs to be set when the explicit discovery file is missing, got apiURL=%q reportURL=%q", conn.GetCloudAPIURL(), conn.GetCloudReportURL())
	}
}
