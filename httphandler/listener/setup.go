package listener

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/metrics"
	"github.com/kubescape/kubescape/v4/httphandler/docs"
	handlerequestsv1 "github.com/kubescape/kubescape/v4/httphandler/handlerequests/v1"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

const (
	scanDrainPeriod            = 20 * time.Second
	applicationShutdownTimeout = 25 * time.Second

	// v1 paths
	v1PathPrefix            = "/v1"
	v1ScanPath              = "/scan"
	v1StatusPath            = "/status"
	v1ResultsPath           = "/results"
	v1PrometheusMetricsPath = "/metrics"

	// healthcheck paths
	livePath  = "/livez"
	readyPath = "/readyz"
)

// SetupHTTPListener serves requests until ctx is cancelled or serving fails.
// Successful shutdown drains HTTP requests and joins the scan worker.
// auth wraps every /v1/* route except /v1/metrics; nil means no wrapping.
func SetupHTTPListener(ctx context.Context, auth func(http.Handler) http.Handler) error {
	tlsReloader, err := newTLSReloader(getCertFile(), getKeyFile())
	if err != nil {
		return err
	}
	addr := fmt.Sprintf(":%s", getPort())
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr: addr,
		// ReadHeaderTimeout defends against slowloris-style attacks without
		// capping handler duration. ReadTimeout and WriteTimeout are left at 0
		// because the synchronous scan path (POST /v1/scan?wait=true) blocks
		// until the scan finishes, which can take minutes. See #2277.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MiB
	}
	if tlsReloader != nil {
		server.TLSConfig = &tls.Config{
			GetCertificate: tlsReloader.GetCertificate,
		}
	}

	httpHandler := handlerequestsv1.NewHTTPHandler(getOffline())

	// Setup the OpenAPI UI handler
	openApiHandler := docs.NewOpenAPIUIHandler()

	rtr := newRouter(httpHandler, openApiHandler, auth)

	// OpenTelemetry metrics initialization
	metrics.Init()

	server.Handler = rtr

	logger.L().Info("Started Kubescape server", helpers.String("port", getPort()), helpers.String("version", versioncheck.BuildNumber))

	servePprof()

	return serveUntilShutdown(ctx, server, ln, httpHandler, scanDrainPeriod, applicationShutdownTimeout)
}

// serveUntilShutdown joins both HTTP draining and the application-owned worker.
// Durations are internal policy, passed explicitly for deterministic tests.
func serveUntilShutdown(ctx context.Context, server *http.Server, ln net.Listener, handler *handlerequestsv1.HTTPHandler, drainPeriod, shutdownTimeout time.Duration) error {
	served := make(chan error, 1)
	go func() {
		if server.TLSConfig != nil {
			served <- server.ServeTLS(ln, "", "")
		} else {
			served <- server.Serve(ln)
		}
	}()
	var serveErr error
	expectedClose := false
	select {
	case serveErr = <-served:
		// A serve failure must also cancel and join application-owned work.
		drainPeriod = 0
	case <-ctx.Done():
		expectedClose = true
		logger.L().Info("Shutting down Kubescape server")
	}
	shutdownStarted := time.Now()
	handler.BeginShutdown()
	shutdownCtx, cancel := context.WithDeadline(context.Background(), shutdownStarted.Add(shutdownTimeout))
	defer cancel()
	workerResult := make(chan error, 1)
	go func() {
		workerResult <- handler.Shutdown(shutdownCtx, time.Until(shutdownStarted.Add(drainPeriod)))
	}()
	httpErr := server.Shutdown(shutdownCtx)
	if httpErr != nil {
		httpErr = errors.Join(httpErr, server.Close())
	}
	workerErr := <-workerResult
	if serveErr == nil {
		serveErr = <-served
	}
	if expectedClose && errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = nil
	}
	err := errors.Join(serveErr, httpErr, workerErr)
	if err == nil {
		logger.L().Info("Kubescape server shutdown complete")
	}
	return err
}

func loadTLSKey(certFile, keyFile string) (*tls.Certificate, error) {
	switch {
	case certFile == "" && keyFile == "":
		return nil, nil
	case certFile == "" || keyFile == "":
		return nil, fmt.Errorf("both KS_CERT_FILE and KS_KEY_FILE must be set to enable TLS (got certFile=%q, keyFile=%q)", certFile, keyFile)
	}

	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load key pair: %w", err)
	}
	return &pair, nil
}

// tlsReloader dynamically reloads TLS certificates and private keys from disk
// when the underlying files are rotated (e.g. by cert-manager or Secret remounts).
type tlsReloader struct {
	certFile string
	keyFile  string

	mu           sync.RWMutex
	cert         *tls.Certificate
	certFileInfo os.FileInfo
	keyFileInfo  os.FileInfo
	certModTime  time.Time
	certSize     int64
	keyModTime   time.Time
	keySize      int64
}

// newTLSReloader creates and initializes a tlsReloader.
// It performs an initial load of the key pair to validate them at startup.
// If both paths are empty, it returns nil, nil (TLS disabled).
// If only one path is set, it returns a validation error.
func newTLSReloader(certFile, keyFile string) (*tlsReloader, error) {
	switch {
	case certFile == "" && keyFile == "":
		return nil, nil
	case certFile == "" || keyFile == "":
		return nil, fmt.Errorf("both KS_CERT_FILE and KS_KEY_FILE must be set to enable TLS (got certFile=%q, keyFile=%q)", certFile, keyFile)
	}

	reloader := &tlsReloader{
		certFile: certFile,
		keyFile:  keyFile,
	}

	if err := reloader.reload(); err != nil {
		return nil, fmt.Errorf("failed to load key pair: %w", err)
	}

	return reloader, nil
}

// GetCertificate returns the current active certificate for incoming TLS handshakes.
// If the certificate or key file has changed on disk, it attempts to reload them.
// If reloading fails, it logs a warning and returns the last known good certificate.
func (r *tlsReloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if r == nil {
		return nil, errors.New("tls reloader is nil")
	}

	if err := r.maybeReload(); err != nil {
		logger.L().Warning("failed to reload TLS key pair, serving existing certificate", helpers.Error(err))
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.cert == nil {
		return nil, errors.New("no TLS certificate available")
	}
	return r.cert, nil
}

// reload reads and parses the certificate and private key files unconditionally,
// recording file metadata.
func (r *tlsReloader) reload() error {
	certStat, err := os.Stat(r.certFile)
	if err != nil {
		return fmt.Errorf("failed to stat cert file %q: %w", r.certFile, err)
	}

	keyStat, err := os.Stat(r.keyFile)
	if err != nil {
		return fmt.Errorf("failed to stat key file %q: %w", r.keyFile, err)
	}

	pair, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("failed to load key pair: %w", err)
	}

	r.mu.Lock()
	r.cert = &pair
	r.certFileInfo = certStat
	r.keyFileInfo = keyStat
	r.certModTime = certStat.ModTime()
	r.certSize = certStat.Size()
	r.keyModTime = keyStat.ModTime()
	r.keySize = keyStat.Size()
	r.mu.Unlock()

	return nil
}

// maybeReload inspects file modification times and sizes. If changed,
// it re-reads the key pair and updates the active certificate.
func (r *tlsReloader) maybeReload() error {
	certStat, err := os.Stat(r.certFile)
	if err != nil {
		return fmt.Errorf("failed to stat cert file: %w", err)
	}

	keyStat, err := os.Stat(r.keyFile)
	if err != nil {
		return fmt.Errorf("failed to stat key file: %w", err)
	}

	r.mu.RLock()
	unchanged := os.SameFile(certStat, r.certFileInfo) &&
		os.SameFile(keyStat, r.keyFileInfo) &&
		certStat.ModTime().Equal(r.certModTime) &&
		certStat.Size() == r.certSize &&
		keyStat.ModTime().Equal(r.keyModTime) &&
		keyStat.Size() == r.keySize
	r.mu.RUnlock()

	if unchanged {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Double check under write lock to avoid redundant loads from concurrent handshakes.
	if os.SameFile(certStat, r.certFileInfo) &&
		os.SameFile(keyStat, r.keyFileInfo) &&
		certStat.ModTime().Equal(r.certModTime) &&
		certStat.Size() == r.certSize &&
		keyStat.ModTime().Equal(r.keyModTime) &&
		keyStat.Size() == r.keySize {
		return nil
	}

	pair, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("failed to load rotated key pair: %w", err)
	}

	r.cert = &pair
	r.certFileInfo = certStat
	r.keyFileInfo = keyStat
	r.certModTime = certStat.ModTime()
	r.certSize = certStat.Size()
	r.keyModTime = keyStat.ModTime()
	r.keySize = keyStat.Size()

	logger.L().Info("reloaded TLS certificate and key pair",
		helpers.String("certFile", r.certFile),
		helpers.String("keyFile", r.keyFile))

	return nil
}

func getOffline() bool {
	return os.Getenv("KS_OFFLINE") == "true"
}

func getPort() string {
	if p := os.Getenv("KS_PORT"); p != "" {
		return p
	}
	return "8080"
}

func getCertFile() string {
	return os.Getenv("KS_CERT_FILE")
}

func getKeyFile() string {
	return os.Getenv("KS_KEY_FILE")
}

func getPprofEnabled() bool {
	return strings.EqualFold(os.Getenv("KS_PPROF_ENABLED"), "true")
}

func getPprofAddr() string {
	if a := os.Getenv("KS_PPROF_ADDR"); a != "" {
		return a
	}
	return "127.0.0.1:6060"
}

// servePprof starts the net/http/pprof debug server, but only when
// explicitly opted into via KS_PPROF_ENABLED=true. It used to start
// automatically whenever the logger level was "debug", which is the
// server's default log level - meaning every deployment exposed
// unauthenticated pprof endpoints (heap dumps, CPU profiling, ...) on
// :6060 by default. It now also binds to loopback only by default (override
// via KS_PPROF_ADDR), so it's reachable only via port-forward/exec into the
// pod, not from the network.
//
// The handlers are registered on a dedicated mux rather than passing nil to
// http.ListenAndServe (which serves off http.DefaultServeMux): the pprof
// package normally self-registers on DefaultServeMux via its own init(), so
// relying on that means these endpoints exist only because some other,
// unrelated package blank-imports "net/http/pprof" - remove that import as
// dead code and this server would silently start logging success while
// serving 404s. Registering explicitly here makes that dependency
// self-contained and compiler-enforced.
//
// Note: importing net/http/pprof anywhere in the binary registers these
// routes on http.DefaultServeMux via that package's init(); serving our own
// mux does not undo that. It's inert here because SetupHTTPListener always
// sets server.Handler, so no server in this binary falls back to the global
// mux - but a future handler-less http.Server would expose them.
func servePprof() {
	if !getPprofEnabled() {
		return
	}
	addr := getPprofAddr()
	srv := newPprofServer(addr)

	go func() {
		logger.L().Info("starting pprof server", helpers.String("address", addr))
		if err := srv.ListenAndServe(); err != nil {
			logger.L().Error("pprof server stopped", helpers.Error(err))
		}
	}()
}

// newPprofServer builds the pprof debug *http.Server on its own dedicated
// mux, so tests can assert on the handler directly instead of probing it
// over the wire (a wire probe can't distinguish a dedicated mux from
// http.DefaultServeMux, since importing net/http/pprof populates the latter
// too - see the DefaultServeMux note on servePprof).
func newPprofServer(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second, // same slowloris guard as the main server
	}
}

// newRouter builds the production mux.
//
// Every /v1/* route except /v1/metrics requires a Kubernetes service-account
// token checked by TokenReview and authorized by RBAC (scans, scanresults in
// kubescape.io), via apiauth. KS_API_AUTH_DISABLED=true turns it off. Health
// probes, the OpenAPI UI and metrics are open.
//
// Rate limiting is intentionally not added here: scan admission already
// enforces bounded queue depth (KS_SCAN_QUEUE_CAPACITY, default 10) with
// 429 + Retry-After and a 1 MiB body cap (KS_SCAN_REQUEST_MAX_BYTES).
func newRouter(httpHandler *handlerequestsv1.HTTPHandler, openApiHandler http.Handler, auth func(http.Handler) http.Handler) *http.ServeMux {
	rtr := http.NewServeMux()

	rtr.HandleFunc("GET "+livePath, httpHandler.Live)
	rtr.HandleFunc("GET "+readyPath, httpHandler.Ready)
	rtr.Handle("GET "+docs.OpenAPIV2Prefix, openApiHandler)

	v1Handler := func(handlerFunc http.HandlerFunc) http.Handler {
		// auth wraps outside otelhttp on purpose: rejected requests are not traced.
		var h http.Handler = otelhttp.NewHandler(handlerFunc, "kubescape-svc")
		if auth != nil {
			h = auth(h)
		}
		return h
	}

	rtr.Handle("GET "+v1PathPrefix+v1PrometheusMetricsPath, otelhttp.NewHandler(http.HandlerFunc(httpHandler.Metrics), "kubescape-svc")) // deprecated, open
	rtr.Handle("POST "+v1PathPrefix+v1ScanPath, v1Handler(httpHandler.Scan))
	rtr.Handle("DELETE "+v1PathPrefix+v1ScanPath, v1Handler(httpHandler.CancelScan))
	rtr.Handle("GET "+v1PathPrefix+v1StatusPath, v1Handler(httpHandler.Status))
	rtr.Handle("GET "+v1PathPrefix+v1ResultsPath, v1Handler(httpHandler.GetResults))
	rtr.Handle("DELETE "+v1PathPrefix+v1ResultsPath, v1Handler(httpHandler.DeleteResults))
	return rtr
}
