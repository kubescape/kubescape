package listener

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/metrics"
	"github.com/kubescape/kubescape/v3/httphandler/docs"
	handlerequestsv1 "github.com/kubescape/kubescape/v3/httphandler/handlerequests/v1"

	"github.com/gorilla/mux"
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
	keyPair, err := loadTLSKey("", "") // TODO - support key and crt files
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr: fmt.Sprintf(":%s", getPort()), // TODO - support loading port from config/env
	}
	if keyPair != nil {
		server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{*keyPair}}
	}

	httpHandler := handlerequestsv1.NewHTTPHandler()

	// Setup the OpenAPI UI handler
	openApiHandler := docs.NewOpenAPIUIHandler()

	rtr := mux.NewRouter()

	// non-monitored endpoints
	rtr.HandleFunc(livePath, httpHandler.Live)
	rtr.HandleFunc(readyPath, httpHandler.Ready)
	rtr.PathPrefix(docs.OpenAPIV2Prefix).Methods("GET").Handler(openApiHandler)

	k8sApi := k8sinterface.NewKubernetesApi()

	// load all CRDs to getter.SaveInFile
	loadExceptions(k8sApi)
	loadControlConfigurations(k8sApi)
	loadRules(k8sApi)
	loadControls(k8sApi)
	loadFrameworks(k8sApi)

	// OpenTelemetry middleware for monitored endpoints
	otelMiddleware := otelmux.Middleware("kubescape-svc")
	v1SubRouter := rtr.PathPrefix(v1PathPrefix).Subrouter()
	v1SubRouter.Use(otelMiddleware)
	v1SubRouter.HandleFunc(v1PrometheusMetricsPath, httpHandler.Metrics)
	v1SubRouter.HandleFunc(v1ScanPath, httpHandler.Scan)
	v1SubRouter.HandleFunc(v1StatusPath, httpHandler.Status)
	v1SubRouter.HandleFunc(v1ResultsPath, httpHandler.Results)

	// watch for changes to crds and update to getter.SaveInFile
	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(k8sApi.DynamicClient, 0, metav1.NamespaceAll, nil)
	exceptionListener(factory)
	controlConfigurationListener(factory)
	ruleListener(factory)
	controlListener(factory)
	frameworkListener(factory)

	// OpenTelemetry metrics initialization
	metrics.Init()

	server.Handler = rtr

	logger.L().Info("Started Kubescape server", helpers.String("port", getPort()), helpers.String("version", cautils.BuildNumber))

	servePprof()

	if keyPair != nil {
		return server.ListenAndServeTLS("", "")
	}
	return server.ListenAndServe()
}

func loadTLSKey(certFile, keyFile string) (*tls.Certificate, error) {
	if keyFile == "" || certFile == "" {
		return nil, nil
	}

	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load key pair: %v", err)
	}
	return &pair, nil
}

func getPort() string {
	if p := os.Getenv("KS_PORT"); p != "" {
		return p
	}
	return "8080"
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
