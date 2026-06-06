package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"time"

	v1 "github.com/kubescape/backend/pkg/client/v1"
	"github.com/kubescape/backend/pkg/servicediscovery"
	"github.com/kubescape/backend/pkg/servicediscovery/schema"
	servicediscoveryv3 "github.com/kubescape/backend/pkg/servicediscovery/v3"
	"github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/go-logger/zaplogger"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	"github.com/kubescape/kubescape/v3/httphandler/config"
	_ "github.com/kubescape/kubescape/v3/httphandler/docs"
	"github.com/kubescape/kubescape/v3/httphandler/listener"
	"github.com/kubescape/kubescape/v3/httphandler/storage"
	"github.com/kubescape/kubescape/v3/pkg/ksinit"
)

// GoReleaser will fill these at build time
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const (
	defaultNamespace = "kubescape"
)

var serviceDiscoveryTimeout = 10 * time.Second

func main() {
	ctx := context.Background()
	versioncheck.BuildNumber = version

	logger.L().Info("Starting Kubescape server",
		helpers.String("version", version),
		helpers.String("commit", commit),
		helpers.String("date", date))

	cfg, err := config.LoadConfig("/etc/config")
	if err != nil {
		logger.L().Ctx(ctx).Error("load config error", helpers.Error(err))
	}

	loadAndSetCredentials()

	clusterName := getClusterName(cfg)

	// to enable otel, set OTEL_COLLECTOR_SVC=otel-collector:4317
	if otelHost, present := os.LookupEnv("OTEL_COLLECTOR_SVC"); present {
		ctx = logger.InitOtel("kubescape",
			version,
			config.GetAccount(),
			clusterName,
			url.URL{Host: otelHost})
		defer logger.ShutdownOtel(ctx)
	}

	logger.L().Debug("setting cluster context name", helpers.String("context", os.Getenv("KS_CONTEXT")))
	k8sinterface.SetClusterContextName(os.Getenv("KS_CONTEXT"))

	initializeLoggerName()
	initializeLoggerLevel()
	initializeSaaSEnv()
	initializeStorage(clusterName, cfg)
	// traces will be created by otelmux.Middleware in SetupHTTPListener()

	logger.L().Ctx(ctx).Fatal(listener.SetupHTTPListener().Error())
}

func initializeStorage(clusterName string, cfg config.Config) {
	namespace := getNamespace(cfg)
	logger.L().Debug("initializing storage", helpers.String("namespace", namespace))

	// Use shared ksinit logic for storage connection
	ksClient, err := ksinit.CreateKsObjectConnection(namespace, 0)
	if err != nil {
		logger.L().Fatal("storage initialization error", helpers.Error(err))
	}

	s, err := storage.NewAPIServerStorage(clusterName, namespace, ksClient, cfg.ContinuousPostureScan)
	if err != nil {
		logger.L().Fatal("storage initialization error", helpers.Error(err))
	}
	storage.SetStorage(s)
}

// initialize logger name
func initializeLoggerName() {
	loggerName := zaplogger.LoggerName
	if l := os.Getenv("KS_LOGGER_NAME"); l != "" {
		loggerName = l
	}
	logger.InitLogger(loggerName)
}

// initialize logger level
func initializeLoggerLevel() {
	loggerLevel := helpers.DebugLevel.String()
	if l := os.Getenv("KS_LOGGER_LEVEL"); l != "" {
		loggerLevel = l
	}
	if err := logger.L().SetLevel(loggerLevel); err != nil {
		logger.L().SetLevel(helpers.DebugLevel.String())
		logger.L().Error("failed to set logger level", helpers.String("level", loggerLevel), helpers.Error(err), helpers.String("default", helpers.DebugLevel.String()))
	}
}

func initializeSaaSEnv() {
	var sdGetter schema.IServiceDiscoveryServiceGetter

	// Prefer file-based discovery: allows sidecar and private-cluster deployments
	// to inject endpoints without network egress to api.armosec.io.
	path := "/etc/config/services.json"
	if p := os.Getenv("KS_SERVICE_DISCOVERY_FILE_PATH"); p != "" {
		path = p
	}
	if _, err := os.Stat(path); err == nil {
		logger.L().Info("using file-based service discovery", helpers.String("path", path))
		sdGetter = servicediscoveryv3.NewServiceDiscoveryFileV3(path)
	} else {
		apiURL := "api.armosec.io"
		if envVar := os.Getenv("API_URL"); envVar != "" {
			logger.L().Debug("API URL updated from env var", helpers.String("url", envVar))
			apiURL = envVar
		}
		client, err := servicediscoveryv3.NewServiceDiscoveryClientV3(apiURL)
		if err != nil {
			logger.L().Fatal("failed to initialize service discovery client", helpers.Error(err))
			return
		}
		sdGetter = client
	}

	backendServices, err := getServicesWithTimeout(sdGetter, serviceDiscoveryTimeout)
	if err != nil {
		logger.L().Warning("failed to get backend services - skipping SaaS wiring", helpers.Error(err))
		return
	}

	if ksCloud, err := v1.NewKSCloudAPI(backendServices.GetApiServerUrl(), backendServices.GetReportReceiverHttpUrl(), config.GetAccount(), config.GetAccessKey()); err != nil {
		logger.L().Fatal("failed to initialize cloud api", helpers.Error(err))
	} else {
		getter.SetKSCloudAPIConnector(ksCloud)
	}
}

// getServicesWithTimeout runs servicediscovery.GetServices in a goroutine and returns
// an error if no response arrives within timeout. This guards against the default
// http.Client (used inside ServiceDiscoveryClientV3) having no request deadline.
func getServicesWithTimeout(g schema.IServiceDiscoveryServiceGetter, timeout time.Duration) (schema.IBackendServices, error) {
	type result struct {
		services schema.IBackendServices
		err      error
	}
	ch := make(chan result, 1)
	go func() {
		s, err := servicediscovery.GetServices(g)
		ch <- result{s, err}
	}()
	select {
	case r := <-ch:
		return r.services, r.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("service discovery timed out after %v", timeout)
	}
}

func getClusterName(cfg config.Config) string {
	if clusterName, ok := os.LookupEnv("CLUSTER_NAME"); ok {
		return clusterName
	}
	return cfg.ClusterName
}

func getNamespace(cfg config.Config) string {
	if ns, ok := os.LookupEnv("NAMESPACE"); ok {
		return ns
	}
	if cfg.Namespace != "" {
		return cfg.Namespace
	}

	return defaultNamespace
}

func loadAndSetCredentials() {
	credentialsPath := "/etc/credentials"
	if envVar := os.Getenv("KS_CREDENTIALS_SECRET_PATH"); envVar != "" {
		credentialsPath = envVar
	}

	credentials, err := utils.LoadCredentialsFromFile(credentialsPath)
	if err != nil {
		logger.L().Error("failed to load credentials", helpers.Error(err))
		// fallback (backward compatibility)
		config.SetAccount(os.Getenv("ACCOUNT_ID"))

		return
	}

	logger.L().Info("credentials loaded from path",
		helpers.String("path", credentialsPath),
		helpers.Int("accessKeyLength", len(credentials.AccessKey)),
		helpers.Int("accountLength", len(credentials.Account)))

	config.SetAccessKey(credentials.AccessKey)
	config.SetAccount(credentials.Account)
}
