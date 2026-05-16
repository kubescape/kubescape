package listener

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/metrics"
	"github.com/kubescape/kubescape/v3/httphandler/docs"
	handlerequestsv1 "github.com/kubescape/kubescape/v3/httphandler/handlerequests/v1"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gorilla/mux/otelmux"
)

const (
	// v1 paths
	v1PathPrefix            = "/v1"
	v1ScanPath              = "/scan"
	v1StatusPath            = "/status"
	v1ResultsPath           = "/results"
	v1PrometheusMetricsPath = "/metrics"

	// healtcheck paths
	livePath  = "/livez"
	readyPath = "/readyz"

	// shutdownGracePeriod is the maximum time to wait for in-flight
	// requests to complete before forcing the server to stop.
	shutdownGracePeriod = 30 * time.Second
)

// SetupHTTPListener sets up the HTTP server and blocks until the server
// is shut down. On SIGTERM or SIGINT the server drains in-flight requests
// for up to shutdownGracePeriod before returning.
func SetupHTTPListener(ctx context.Context) error {
	keyPair, err := loadTLSKey(getCertFile(), getKeyFile())
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr: fmt.Sprintf(":%s", getPort()),
	}
	if keyPair != nil {
		server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{*keyPair}}
	}

	httpHandler := handlerequestsv1.NewHTTPHandler(getOffline())

	// Setup the OpenAPI UI handler
	openApiHandler := docs.NewOpenAPIUIHandler()

	rtr := mux.NewRouter()

	// non-monitored endpoints
	rtr.HandleFunc(livePath, httpHandler.Live)
	rtr.HandleFunc(readyPath, httpHandler.Ready)
	rtr.PathPrefix(docs.OpenAPIV2Prefix).Methods("GET").Handler(openApiHandler)

	// OpenTelemetry middleware for monitored endpoints
	otelMiddleware := otelmux.Middleware("kubescape-svc")
	v1SubRouter := rtr.PathPrefix(v1PathPrefix).Subrouter()
	v1SubRouter.Use(otelMiddleware)
	v1SubRouter.HandleFunc(v1PrometheusMetricsPath, httpHandler.Metrics) // deprecated
	v1SubRouter.HandleFunc(v1ScanPath, httpHandler.Scan)
	v1SubRouter.HandleFunc(v1StatusPath, httpHandler.Status)
	v1SubRouter.HandleFunc(v1ResultsPath, httpHandler.Results)

	// OpenTelemetry metrics initialization
	metrics.Init()

	server.Handler = rtr

	logger.L().Info("Started Kubescape server", helpers.String("port", getPort()), helpers.String("version", versioncheck.BuildNumber))

	servePprof()

	// Start the server in a goroutine so we can listen for shutdown signals.
	errCh := make(chan error, 1)
	go func() {
		var listenErr error
		if keyPair != nil {
			listenErr = server.ListenAndServeTLS("", "")
		} else {
			listenErr = server.ListenAndServe()
		}
		// ErrServerClosed is returned by Shutdown — not an error.
		if listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
			errCh <- listenErr
		}
		close(errCh)
	}()

	// Block until a termination signal or a listener error.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-sigCh:
		logger.L().Info("received shutdown signal, draining in-flight requests",
			helpers.String("signal", sig.String()))
	case err := <-errCh:
		// Listener failed to start (e.g. port conflict).
		return err
	case <-ctx.Done():
		logger.L().Info("context cancelled, shutting down server")
	}

	// Graceful shutdown: give in-flight requests time to complete.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGracePeriod)
	defer cancel()

	logger.L().Info("shutting down HTTP server",
		helpers.String("gracePeriod", shutdownGracePeriod.String()))

	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown error: %w", err)
	}

	logger.L().Info("HTTP server stopped gracefully")
	return nil
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

func servePprof() {
	go func() {
		// start pprof server -> https://pkg.go.dev/net/http/pprof
		if logger.L().GetLevel() == helpers.DebugLevel.String() {
			logger.L().Info("starting pprof server", helpers.String("port", "6060"))
			logger.L().Error(http.ListenAndServe(":6060", nil).Error())
		}
	}()
}
