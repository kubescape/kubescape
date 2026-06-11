package listener

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"
	"github.com/gorilla/mux"
	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/metrics"
	"github.com/kubescape/kubescape/v3/httphandler/docs"
		ReadTimeout:       getDurationFromEnv(envReadTimeout, defaultReadTimeout),

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
		if parsed < 0 {
			logger.L().Warning("negative duration for env var, using default",
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

<<<<<<< HEAD
func getCertFile() string {
	return os.Getenv("KS_CERT_FILE")
}

func getKeyFile() string {
	return os.Getenv("KS_KEY_FILE")
=======
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
		if parsed < 0 {
			logger.L().Warning("negative duration for env var, using default",
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
>>>>>>> 7173a590 (Add HTTP server timeouts and header limits)
}

func servePprof() {
	go func() {
		// start pprof server -> https://pkg.go.dev/net/http/pprof
		if logger.L().GetLevel() == helpers.DebugLevel.String() {
			logger.L().Info("starting pprof server", helpers.String("port", "6060"))
			pprofServer := &http.Server{
				Addr:              ":6060",
				ReadHeaderTimeout: getDurationFromEnv(envReadHeaderTimeout, defaultReadHeaderTimeout),
				ReadTimeout:       getDurationFromEnv(envReadTimeout, defaultReadTimeout),
				WriteTimeout:      getDurationFromEnv(envWriteTimeout, defaultWriteTimeout),
				IdleTimeout:       getDurationFromEnv(envIdleTimeout, defaultIdleTimeout),
				MaxHeaderBytes:    getMaxHeaderBytes(),
			}
			logger.L().Error(pprofServer.ListenAndServe().Error())
		}
	}()
}
