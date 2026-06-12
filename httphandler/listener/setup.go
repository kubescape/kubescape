package listener

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"strconv"
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

// HTTP listener constants
const (
	defaultPort      = "8080"
	envPort          = "KS_PORT"
	envCertFile      = "KS_CERT_FILE"
	envKeyFile       = "KS_KEY_FILE"
	envOffline       = "KS_OFFLINE"
	defaultPprofPort = "6060"
	envPprofPort     = "KS_PPROF_PORT"
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
)

const (
	envReadHeaderTimeout = "KS_HTTP_READ_HEADER_TIMEOUT"
	envReadTimeout       = "KS_HTTP_READ_TIMEOUT"
	envWriteTimeout      = "KS_HTTP_WRITE_TIMEOUT"
	envIdleTimeout       = "KS_HTTP_IDLE_TIMEOUT"
	envMaxHeaderBytes    = "KS_HTTP_MAX_HEADER_BYTES"
)

const (
	defaultReadHeaderTimeout = 10 * time.Second
	defaultReadTimeout       = 30 * time.Second
	defaultWriteTimeout      = 15 * time.Minute
	defaultIdleTimeout       = 2 * time.Minute
	defaultMaxHeaderBytes    = http.DefaultMaxHeaderBytes
)

// SetupHTTPListener set up listening http servers
func SetupHTTPListener() error {
	keyPair, err := loadTLSKey(getCertFile(), getKeyFile())
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              fmt.Sprintf(":%s", getPort()), // TODO - support loading port from config/env
		ReadHeaderTimeout: getDurationFromEnv(envReadHeaderTimeout, defaultReadHeaderTimeout),
		ReadTimeout:       getDurationFromEnv(envReadTimeout, defaultReadTimeout),
		WriteTimeout:      getDurationFromEnv(envWriteTimeout, defaultWriteTimeout),
		IdleTimeout:       getDurationFromEnv(envIdleTimeout, defaultIdleTimeout),
		MaxHeaderBytes:    getMaxHeaderBytes(),
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

	if keyPair != nil {
		return server.ListenAndServeTLS("", "")
	}
	return server.ListenAndServe()
}

func loadTLSKey(certFile, keyFile string) (*tls.Certificate, error) {
	switch {
	case certFile == "" && keyFile == "":
		return nil, nil
	case certFile != "" && keyFile != "":
		keyPair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load key pair: %v", err)
		}
		return &keyPair, nil
	default:
		return nil, fmt.Errorf("both %s and %s must be set to enable TLS (got certFile=%q, keyFile=%q)", envCertFile, envKeyFile, certFile, keyFile)
	}
}

func getPort() string {
	if p := os.Getenv(envPort); p != "" {
		return p
	}
	return defaultPort
}

func getCertFile() string {
	return os.Getenv(envCertFile)
}

func getKeyFile() string {
	return os.Getenv(envKeyFile)
}

func getOffline() bool {
	return os.Getenv(envOffline) == "true"
}

func getPprofPort() string {
	if p := os.Getenv(envPprofPort); p != "" {
		return p
	}
	return defaultPprofPort
}

func servePprof() {
	if logger.L().GetLevel() != helpers.DebugLevel.String() {
		return
	}

	pprofPort := getPprofPort()
	pprofMux := http.NewServeMux()
	pprofMux.HandleFunc("/debug/pprof/", pprof.Index)
	pprofMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	pprofMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	pprofMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	pprofMux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	pprofServer := &http.Server{
		Addr:              fmt.Sprintf(":%s", pprofPort),
		Handler:           pprofMux,
		ReadHeaderTimeout: getDurationFromEnv(envReadHeaderTimeout, defaultReadHeaderTimeout),
		ReadTimeout:       getDurationFromEnv(envReadTimeout, defaultReadTimeout),
		WriteTimeout:      getDurationFromEnv(envWriteTimeout, defaultWriteTimeout),
		IdleTimeout:       getDurationFromEnv(envIdleTimeout, defaultIdleTimeout),
		MaxHeaderBytes:    getMaxHeaderBytes(),
	}

	go func() {
		logger.L().Info("starting pprof server", helpers.String("port", pprofPort))
		if err := pprofServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.L().Error("failed to serve pprof", helpers.Error(err))
		}
	}()
}

func getDurationFromEnv(envVar string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(envVar); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			logger.L().Warning("invalid duration for env var, using default",
				helpers.String("env", envVar),
				helpers.String("value", value),
				helpers.Error(err),
				helpers.String("default", defaultValue.String()))
			return defaultValue
		}
		if parsed <= 0 {
			logger.L().Warning("non-positive duration for env var, using default",
				helpers.String("env", envVar),
				helpers.String("value", value),
				helpers.String("default", defaultValue.String()))
			return defaultValue
		}
		return parsed
	}

	return defaultValue
}

func getMaxHeaderBytes() int {
	if value := os.Getenv(envMaxHeaderBytes); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed <= 0 {
			logger.L().Warning("invalid max header bytes value, using default",
				helpers.String("env", envMaxHeaderBytes),
				helpers.String("value", value),
				helpers.Int("default", defaultMaxHeaderBytes))
			return defaultMaxHeaderBytes
		}
		return parsed
	}

	return defaultMaxHeaderBytes
}
