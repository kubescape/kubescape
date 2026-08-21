package listener

import (
	"crypto/subtle"
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
	"github.com/kubescape/kubescape/v4/core/metrics"
	"github.com/kubescape/kubescape/v4/httphandler/docs"
	handlerequestsv1 "github.com/kubescape/kubescape/v4/httphandler/handlerequests/v1"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gorilla/mux/otelmux"
)

const (
	// v1 paths
	v1PathPrefix            = "/v1"
	v1ScanPath              = "/scan"
	v1StatusPath            = "/status"
	v1ResultsPath           = "/results"
	v1PrometheusMetricsPath = "/metrics"

	// healthcheck paths
	livePath  = "/livez"
	readyPath = "/readyz"

	// authTokenEnv gates optional bearer-token auth for /v1/*. When set, every
	// /v1/* request must present `Authorization: Bearer <token>`. When unset the
	// listener remains unauthenticated for backward compatibility (in-cluster only).
	authTokenEnv = "KS_API_TOKEN"
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
		Addr: addr,
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

	// Health probes are intentionally unauthenticated — kubelet needs them without credentials.
	rtr.HandleFunc(livePath, httpHandler.Live)
	rtr.HandleFunc(readyPath, httpHandler.Ready)
	rtr.PathPrefix(docs.OpenAPIV2Prefix).Methods("GET").Handler(openApiHandler)

	// -------------------------------------------------------------------------
	// Trust boundary for /v1/* (scan trigger + results):
	// By default the listener is unauthenticated and intended to be reachable
	// only inside the cluster (ClusterIP / port-forward). This matches the
	// historical in-cluster microservice deployment and preserves backward
	// compatibility.
	//
	// If the operator exposes :8080 beyond the cluster (LoadBalancer, Ingress,
	// NodePort on a public node), set KS_API_TOKEN to a cryptographically
	// random bearer token. When set, every /v1/* request must present
	// `Authorization: Bearer <token>`; otherwise 401 is returned. This is
	// opt-in so existing in-cluster installs do not break on upgrade — see
	// getAuthToken / bearerAuthMiddleware below. Unlike pprof (servePprof),
	// which is off by default, the scan API is on by default because it is
	// the product surface; the hardening is therefore additive and env-gated.
	//
	// Rate limiting is intentionally not added here: scan admission already
	// enforces bounded queue depth (KS_SCAN_QUEUE_CAPACITY, default 10) with
	// 429 + Retry-After and a 1 MiB body cap (KS_SCAN_REQUEST_MAX_BYTES).
	// External L7 rate limiting should be done at the Ingress if needed.
	// -------------------------------------------------------------------------
	otelMiddleware := otelmux.Middleware("kubescape-svc")
	v1SubRouter := rtr.PathPrefix(v1PathPrefix).Subrouter()
	v1SubRouter.Use(otelMiddleware)
	if tok := getAuthToken(); tok != "" {
		logger.L().Info("API token authentication enabled for /v1/* endpoints", helpers.String("env", authTokenEnv))
	} else {
		logger.L().Warning("API token not configured — /v1/* endpoints are unauthenticated; ensure the service is not exposed beyond the cluster", helpers.String("env", authTokenEnv))
	}
	v1SubRouter.Use(bearerAuthMiddleware)
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

	defer httpHandler.Shutdown()

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

func getPprofEnabled() bool {
	return strings.EqualFold(os.Getenv("KS_PPROF_ENABLED"), "true")
}

func getPprofAddr() string {
	if a := os.Getenv("KS_PPROF_ADDR"); a != "" {
		return a
	}
	return "127.0.0.1:6060"
}

func getAuthToken() string {
	return strings.TrimSpace(os.Getenv(authTokenEnv))
}

// bearerAuthMiddleware enforces `Authorization: Bearer <token>` when KS_API_TOKEN is set.
// When the env var is unset/empty it is a no-op for backward compatibility.
// It uses subtle.ConstantTimeCompare to avoid timing side-channels.
func bearerAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := getAuthToken()
		if expected == "" {
			next.ServeHTTP(w, r)
			return
		}
		hdr := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(hdr, prefix) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="kubescape"`)
			http.Error(w, `{"error":"missing or invalid Authorization header"}`, http.StatusUnauthorized)
			return
		}
		got := strings.TrimSpace(strings.TrimPrefix(hdr, prefix))
		if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="kubescape"`)
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
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
