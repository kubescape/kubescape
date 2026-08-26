package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/backend/pkg/servicediscovery/schema"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/go-logger/zaplogger"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/httphandler/config"
	"github.com/kubescape/kubescape/v4/httphandler/storage"
)

// validServicesV3JSON is a minimal well-formed service-discovery v3 payload.
const validServicesV3JSON = `{"version":"v3","response":{"api-server":"https://api.test.io","event-receiver-http":"https://report.test.io"}}`

// withNoneLogger swaps in the "none" logger (whose Fatal is a no-op) so that
// production Fatal paths can be exercised in-process instead of killing the
// test binary via os.Exit. The pre-test logger is restored on cleanup so this
// doesn't leak into unrelated tests.
func withNoneLogger(t *testing.T) {
	t.Helper()
	orig := logger.L().LoggerName()
	logger.InitLogger("none")
	t.Cleanup(func() { logger.InitLogger(orig) })
}

// withZapLogger installs a fresh zap logger as a known baseline for
// level-related assertions (GetLevel() reports a parseable level string) and
// restores the pre-test logger on cleanup.
func withZapLogger(t *testing.T) {
	t.Helper()
	orig := logger.L().LoggerName()
	logger.InitLogger(zaplogger.LoggerName)
	t.Cleanup(func() { logger.InitLogger(orig) })
}

// resetSaaSState clears the package-level account/access-key/cloud-connector
// globals that initializeSaaSEnv reads and mutates, and restores the pre-test
// values on cleanup. Without this, tests that run earlier (e.g. credential
// loading) can leak state into SaaS wiring assertions and vice versa.
func resetSaaSState(t *testing.T) {
	t.Helper()
	origAccount, origAccessKey := config.GetAccount(), config.GetAccessKey()
	origConnector := getter.GetKSCloudAPIConnector()
	config.SetAccount("")
	config.SetAccessKey("")
	getter.SetKSCloudAPIConnector(nil)
	t.Cleanup(func() {
		config.SetAccount(origAccount)
		config.SetAccessKey(origAccessKey)
		getter.SetKSCloudAPIConnector(origConnector)
	})
}

// noRealServiceDiscoveryFile points defaultServiceDiscoveryPath at a path
// that doesn't exist and clears KS_SERVICE_DISCOVERY_FILE_PATH, so that
// initializeSaaSEnv falls through to the network-discovery branch instead of
// the file-based one. The original defaultServiceDiscoveryPath is restored on
// cleanup.
func noRealServiceDiscoveryFile(t *testing.T) {
	t.Helper()
	origDefaultPath := defaultServiceDiscoveryPath
	defaultServiceDiscoveryPath = filepath.Join(t.TempDir(), "no-services.json")
	t.Cleanup(func() { defaultServiceDiscoveryPath = origDefaultPath })
	t.Setenv("KS_SERVICE_DISCOVERY_FILE_PATH", "")
}

// TestInitializeSaaSEnv_fileSuccess verifies that a valid services.json causes
// initializeSaaSEnv to wire up the cloud connector with the discovered URLs.
func TestInitializeSaaSEnv_fileSuccess(t *testing.T) {
	resetSaaSState(t)

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

	conn := getter.GetKSCloudAPIConnector()
	if got := conn.GetCloudAPIURL(); got != "https://api.test.io" {
		t.Errorf("expected cloud API URL https://api.test.io, got %q", got)
	}
	if got := conn.GetCloudReportURL(); got != "https://report.test.io" {
		t.Errorf("expected cloud report URL https://report.test.io, got %q", got)
	}
}

// TestInitializeSaaSEnv_apiSuccess verifies that a reachable API endpoint causes
// initializeSaaSEnv to wire up the cloud connector with the discovered URLs.
func TestInitializeSaaSEnv_apiSuccess(t *testing.T) {
	resetSaaSState(t)
	noRealServiceDiscoveryFile(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/servicediscovery" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(validServicesV3JSON))
	}))
	t.Cleanup(srv.Close)

	// srv.URL is "http://127.0.0.1:PORT" — ParseHost preserves the http scheme.
	t.Setenv("API_URL", srv.URL)

	origTimeout := serviceDiscoveryTimeout
	serviceDiscoveryTimeout = 5 * time.Second
	t.Cleanup(func() { serviceDiscoveryTimeout = origTimeout })

	initializeSaaSEnv()

	conn := getter.GetKSCloudAPIConnector()
	if got := conn.GetCloudAPIURL(); got != "https://api.test.io" {
		t.Errorf("expected cloud API URL https://api.test.io, got %q", got)
	}
	if got := conn.GetCloudReportURL(); got != "https://report.test.io" {
		t.Errorf("expected cloud report URL https://report.test.io, got %q", got)
	}
}

// TestInitializeSaaSEnv_networkFailure verifies that a transient network error
// causes initializeSaaSEnv to log a warning and return instead of crashing,
// leaving the cloud connector unset.
func TestInitializeSaaSEnv_networkFailure(t *testing.T) {
	resetSaaSState(t)
	noRealServiceDiscoveryFile(t)

	// Port 1 refuses connections immediately on loopback.
	t.Setenv("API_URL", "http://127.0.0.1:1")

	origTimeout := serviceDiscoveryTimeout
	serviceDiscoveryTimeout = 50 * time.Millisecond
	t.Cleanup(func() { serviceDiscoveryTimeout = origTimeout })

	initializeSaaSEnv() // must log a warning and return, not call Fatal/os.Exit

	conn := getter.GetKSCloudAPIConnector()
	if conn.GetCloudAPIURL() != "" || conn.GetCloudReportURL() != "" {
		t.Fatalf("expected no cloud connector URLs to be set after a network failure, got apiURL=%q reportURL=%q", conn.GetCloudAPIURL(), conn.GetCloudReportURL())
	}
}

// TestInitializeSaaSEnv_noBackendConfigured verifies that with no service-discovery
// file, no API_URL, and no account/accessKey, initializeSaaSEnv skips SaaS wiring
// entirely (no network call, no cloud connector set) - see
// https://github.com/kubescape/kubescape/issues/2555.
func TestInitializeSaaSEnv_noBackendConfigured(t *testing.T) {
	resetSaaSState(t)
	noRealServiceDiscoveryFile(t)

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
	resetSaaSState(t)

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

// slowGetter implements schema.IServiceDiscoveryServiceGetter but blocks
// longer than any reasonable test timeout, forcing the timeout branch of
// getServicesWithTimeout.
type slowGetter struct{ delay time.Duration }

func (s slowGetter) Get() (io.Reader, error) {
	time.Sleep(s.delay)
	return strings.NewReader(validServicesV3JSON), nil
}

func (s slowGetter) ParseResponse(json.RawMessage) (schema.IBackendServices, error) {
	return nil, nil
}

func TestGetServicesWithTimeout_timesOut(t *testing.T) {
	_, err := getServicesWithTimeout(slowGetter{delay: 200 * time.Millisecond}, 20*time.Millisecond)
	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got: %v", err)
	}
}

// TestInitializeSaaSEnv_clientCreationError forces servicediscoveryv3.NewServiceDiscoveryClientV3
// to fail (invalid URL containing a control character) and verifies the Fatal
// path is taken without crashing the test binary.
//
// The discovery-file path must be reached via defaultServiceDiscoveryPath, not
// an explicit KS_SERVICE_DISCOVERY_FILE_PATH: an explicit-but-missing path
// short-circuits into the "configured file not found" branch before ever
// calling NewServiceDiscoveryClientV3, which would make this test pass
// without exercising the code path it claims to cover.
func TestInitializeSaaSEnv_clientCreationError(t *testing.T) {
	withNoneLogger(t)
	resetSaaSState(t)
	noRealServiceDiscoveryFile(t)

	t.Setenv("API_URL", "http://exa\nmple.com")

	initializeSaaSEnv() // Fatal is a no-op with the none logger; must not exit the process

	conn := getter.GetKSCloudAPIConnector()
	if conn.GetCloudAPIURL() != "" || conn.GetCloudReportURL() != "" {
		t.Fatalf("expected no cloud connector URLs to be set when client creation fails, got apiURL=%q reportURL=%q", conn.GetCloudAPIURL(), conn.GetCloudReportURL())
	}
}

// TestInitializeSaaSEnv_cloudApiError forces v1.NewKSCloudAPI to fail by
// supplying an api-server URL containing a control character via the
// file-based discovery path, and verifies the resulting Fatal call is a no-op.
func TestInitializeSaaSEnv_cloudApiError(t *testing.T) {
	withNoneLogger(t)
	resetSaaSState(t)

	// The \n here is a JSON escape sequence (two chars: backslash, n), which the
	// JSON decoder turns into an actual newline byte inside the decoded Go string —
	// a valid control character that later trips up url.Parse in NewKSCloudAPI.
	badServicesJSON := `{"version":"v3","response":{"api-server":"https://exa\nmple.io","event-receiver-http":"https://report.test.io"}}`

	f, err := os.CreateTemp(t.TempDir(), "services*.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(badServicesJSON); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()

	t.Setenv("KS_SERVICE_DISCOVERY_FILE_PATH", f.Name())

	initializeSaaSEnv() // Fatal is a no-op with the none logger; must not exit the process

	conn := getter.GetKSCloudAPIConnector()
	if conn.GetCloudAPIURL() != "" || conn.GetCloudReportURL() != "" {
		t.Fatalf("expected no cloud connector URLs to be set when cloud API creation fails, got apiURL=%q reportURL=%q", conn.GetCloudAPIURL(), conn.GetCloudReportURL())
	}
}

func TestInitializeLoggerName_default(t *testing.T) {
	orig := logger.L().LoggerName()
	t.Cleanup(func() { logger.InitLogger(orig) })

	t.Setenv("KS_LOGGER_NAME", "")
	initializeLoggerName()

	if got := logger.L().LoggerName(); got != zaplogger.LoggerName {
		t.Fatalf("expected default logger %q, got %q", zaplogger.LoggerName, got)
	}
}

func TestInitializeLoggerName_envOverride(t *testing.T) {
	orig := logger.L().LoggerName()
	t.Cleanup(func() { logger.InitLogger(orig) })

	t.Setenv("KS_LOGGER_NAME", "icon")
	initializeLoggerName()

	if got := logger.L().LoggerName(); got != "icon" {
		t.Fatalf("expected icon logger, got %q", got)
	}
}

func TestInitializeLoggerLevel_default(t *testing.T) {
	withZapLogger(t)

	t.Setenv("KS_LOGGER_LEVEL", "")
	initializeLoggerLevel()

	if got := logger.L().GetLevel(); got != helpers.DebugLevel.String() {
		t.Fatalf("expected default level %q, got %q", helpers.DebugLevel.String(), got)
	}
}

func TestInitializeLoggerLevel_envOverride(t *testing.T) {
	withZapLogger(t)

	t.Setenv("KS_LOGGER_LEVEL", "info")
	initializeLoggerLevel()

	if got := logger.L().GetLevel(); got != helpers.InfoLevel.String() {
		t.Fatalf("expected level %q, got %q", helpers.InfoLevel.String(), got)
	}
}

func TestInitializeLoggerLevel_invalidLevel(t *testing.T) {
	withZapLogger(t)

	t.Setenv("KS_LOGGER_LEVEL", "not-a-real-level")
	initializeLoggerLevel() // must log an error and fall back to debug, not crash

	if got := logger.L().GetLevel(); got != helpers.DebugLevel.String() {
		t.Fatalf("expected fallback to default level %q, got %q", helpers.DebugLevel.String(), got)
	}
}

func TestGetClusterName_envOverride(t *testing.T) {
	t.Setenv("CLUSTER_NAME", "env-cluster")
	if got := getClusterName(config.Config{ClusterName: "cfg-cluster"}); got != "env-cluster" {
		t.Fatalf("expected env-cluster, got %s", got)
	}
}

func TestGetClusterName_configFallback(t *testing.T) {
	t.Setenv("CLUSTER_NAME", "") // records the original + registers restore-on-cleanup
	os.Unsetenv("CLUSTER_NAME")  // actually clears it for this test
	if got := getClusterName(config.Config{ClusterName: "cfg-cluster"}); got != "cfg-cluster" {
		t.Fatalf("expected cfg-cluster, got %s", got)
	}
}

func TestGetNamespace_envOverride(t *testing.T) {
	t.Setenv("NAMESPACE", "env-ns")
	if got := getNamespace(config.Config{Namespace: "cfg-ns"}); got != "env-ns" {
		t.Fatalf("expected env-ns, got %s", got)
	}
}

func TestGetNamespace_configFallback(t *testing.T) {
	t.Setenv("NAMESPACE", "") // records the original + registers restore-on-cleanup
	os.Unsetenv("NAMESPACE")  // actually clears it for this test
	if got := getNamespace(config.Config{Namespace: "cfg-ns"}); got != "cfg-ns" {
		t.Fatalf("expected cfg-ns, got %s", got)
	}
}

func TestGetNamespace_defaultFallback(t *testing.T) {
	t.Setenv("NAMESPACE", "") // records the original + registers restore-on-cleanup
	os.Unsetenv("NAMESPACE")  // actually clears it for this test
	if got := getNamespace(config.Config{}); got != defaultNamespace {
		t.Fatalf("expected %s, got %s", defaultNamespace, got)
	}
}

func TestLoadAndSetCredentials_success(t *testing.T) {
	resetSaaSState(t)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "accessKey"), []byte("my-access-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "account"), []byte("my-account\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KS_CREDENTIALS_SECRET_PATH", dir)

	loadAndSetCredentials()

	if got := config.GetAccessKey(); got != "my-access-key" {
		t.Fatalf("expected my-access-key, got %s", got)
	}
	if got := config.GetAccount(); got != "my-account" {
		t.Fatalf("expected my-account, got %s", got)
	}
}

func TestLoadAndSetCredentials_missingFilesFallback(t *testing.T) {
	resetSaaSState(t)

	t.Setenv("KS_CREDENTIALS_SECRET_PATH", t.TempDir())
	t.Setenv("ACCOUNT_ID", "fallback-account")

	loadAndSetCredentials()

	if got := config.GetAccount(); got != "fallback-account" {
		t.Fatalf("expected fallback-account, got %s", got)
	}
	if got := config.GetAccessKey(); got != "" {
		t.Fatalf("expected no access key to be set on fallback, got %s", got)
	}
}

// fakeKubeconfig is a minimal, well-formed kubeconfig. clientcmd only parses
// and validates this file's shape; building a rest.Config and a typed client
// from it performs no network I/O, so this is safe to use in unit tests.
const fakeKubeconfig = `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:6443
    insecure-skip-tls-verify: true
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: test-user
  name: test-context
current-context: test-context
users:
- name: test-user
  user:
    token: fake-token
`

func TestInitializeStorage_success(t *testing.T) {
	origStorage := storage.GetStorage()
	t.Cleanup(func() { storage.SetStorage(origStorage) })

	dir := t.TempDir()
	kubeconfigPath := filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(kubeconfigPath, []byte(fakeKubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", kubeconfigPath)

	initializeStorage("test-cluster", config.Config{Namespace: "ks-ns"})

	s := storage.GetStorage()
	if s == nil {
		t.Fatal("expected storage to be set")
	}
	if s.StorageClient == nil {
		t.Fatal("expected storage client to be set from the valid kubeconfig")
	}
}

// TestInitializeStorage_connectionError forces ksinit.CreateKsObjectConnection
// to fail (no usable KUBECONFIG, no ~/.kube/config, and not running in-cluster)
// and verifies the resulting Fatal call is a no-op rather than crashing the
// test binary, and that initializeStorage returns without touching the
// package-global storage singleton.
func TestInitializeStorage_connectionError(t *testing.T) {
	withNoneLogger(t)

	origStorage := storage.GetStorage()
	t.Cleanup(func() { storage.SetStorage(origStorage) })

	emptyHome := t.TempDir()
	t.Setenv("HOME", emptyHome)
	t.Setenv("KUBECONFIG", "") // records the original + registers restore-on-cleanup
	os.Unsetenv("KUBECONFIG")  // actually clears it for this test
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	os.Unsetenv("KUBERNETES_SERVICE_HOST")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	os.Unsetenv("KUBERNETES_SERVICE_PORT")

	initializeStorage("test-cluster", config.Config{Namespace: "ks-ns"})

	if got := storage.GetStorage(); got != origStorage {
		t.Fatalf("expected storage to be left untouched after a connection error, got %v, want %v", got, origStorage)
	}
}
