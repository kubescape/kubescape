package main

import (
	"context"
	"net/url"
	"os"

	v1 "github.com/kubescape/backend/pkg/client/v1"
	"github.com/kubescape/backend/pkg/servicediscovery"
	servicediscoveryv2 "github.com/kubescape/backend/pkg/servicediscovery/v2"
	"github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/backend/pkg/versioncheck"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/go-logger/zaplogger"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	"github.com/kubescape/kubescape/v3/httphandler/config"
	_ "github.com/kubescape/kubescape/v3/httphandler/docs"
	"github.com/kubescape/kubescape/v3/httphandler/listener"
	"github.com/kubescape/kubescape/v3/httphandler/storage"
	"k8s.io/client-go/rest"
)

const (
	defaultNamespace = "kubescape"
)

func main() {
	ctx := context.Background()

	cfg, err := config.LoadConfig("/etc/config")
	if err != nil {
		logger.L().Ctx(ctx).Error("load config error", helpers.Error(err))
	}

	loadAndSetCredentials()

	clusterName := getClusterName(cfg)

	// to enable otel, set OTEL_COLLECTOR_SVC=otel-collector:4317
	if otelHost, present := os.LookupEnv("OTEL_COLLECTOR_SVC"); present {
		ctx = logger.InitOtel("kubescape",
			os.Getenv(versioncheck.BuildNumber),
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
	if !cfg.ContinuousPostureScan {
		logger.L().Debug("continuous posture scan - skipping storage initialization")
		return
	}
	namespace := getNamespace(cfg)
	logger.L().Debug("initializing storage", helpers.String("namespace", namespace))

	// for local storage, use the k8s config
	var config *rest.Config
	if os.Getenv("LOCAL_STORAGE") == "true" {
		config = k8sinterface.GetK8sConfig()
	} else {
		var err error
		config, err = rest.InClusterConfig()
		if err != nil {
			logger.L().Fatal("storage initialization error", helpers.Error(err))
		}
	}

	s, err := storage.NewAPIServerStorage(clusterName, namespace, config)
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
	serviceDiscoveryFilePath := "/etc/config/services.json"
	if envVar := os.Getenv("KS_SERVICE_DISCOVERY_FILE_PATH"); envVar != "" {
		logger.L().Debug("service discovery file path updated from env var", helpers.String("path", envVar))
		serviceDiscoveryFilePath = envVar
	}

	if _, err := os.Stat(serviceDiscoveryFilePath); err != nil {
		logger.L().Info("service discovery file not found - skipping", helpers.String("path", serviceDiscoveryFilePath))
		return
	}

	backendServices, err := servicediscovery.GetServices(
		servicediscoveryv2.NewServiceDiscoveryFileV2(serviceDiscoveryFilePath),
	)
	if err != nil {
		logger.L().Fatal("failed to get backend services", helpers.Error(err))
		return
	}

	if ksCloud, err := v1.NewKSCloudAPI(backendServices.GetApiServerUrl(), backendServices.GetReportReceiverHttpUrl(), config.GetAccount(), config.GetAccessKey()); err != nil {
		logger.L().Fatal("failed to initialize cloud api", helpers.Error(err))
	} else {
		getter.SetKSCloudAPIConnector(ksCloud)
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
