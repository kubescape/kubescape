package listener

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
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
)

// SetupHTTPListener set up listening http servers
func SetupHTTPListener() error {
	keyPair, err := loadTLSKey(getCertFile(), getKeyFile())
	if err != nil {
		return err
	}
	addr := fmt.Sprintf(":%s", getPort())
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr: addr, // TODO - support loading port from config/env
		// ReadHeaderTimeout defends against slowloris-style attacks without
		// capping handler duration. ReadTimeout and WriteTimeout are left at 0
		// because the synchronous scan path (POST /v1/scan?wait=true) blocks
		// until the scan finishes, which can take minutes. See #2277.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MiB
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
	v1SubRouter.HandleFunc(v1ScanPath, httpHandler.Scan).Methods(http.MethodPost)
	v1SubRouter.HandleFunc(v1ScanPath, httpHandler.CancelScan).Methods(http.MethodDelete)
	v1SubRouter.HandleFunc(v1StatusPath, httpHandler.Status)
	v1SubRouter.HandleFunc(v1ResultsPath, httpHandler.GetResults).Methods(http.MethodGet)
	v1SubRouter.HandleFunc(v1ResultsPath, httpHandler.DeleteResults).Methods(http.MethodDelete)

	// OpenTelemetry metrics initialization
	metrics.Init()

	server.Handler = rtr

	logger.L().Info("Started Kubescape server", helpers.String("port", getPort()), helpers.String("version", versioncheck.BuildNumber))

	servePprof()

	if keyPair != nil {
		return server.ServeTLS(ln, "", "")
	}
	return server.Serve(ln)
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
		return nil, fmt.Errorf("failed to load key pair: %v", err)
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
// serving 404s. Registering explicitly here also keeps profiling handlers
// off the global DefaultServeMux, so a future handler-less http.Server
// elsewhere in this binary can't accidentally re-expose them.
func servePprof() {
	if !getPprofEnabled() {
		return
	}
	addr := getPprofAddr()

	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second, // same slowloris guard as the main server
	}

	go func() {
		logger.L().Info("starting pprof server", helpers.String("address", addr))
		if err := srv.ListenAndServe(); err != nil {
			logger.L().Error("pprof server stopped", helpers.Error(err))
		}
	}()
}
