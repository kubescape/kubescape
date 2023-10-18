package main

import (
	"context"
	"net/url"
	"os"

	v1 "github.com/kubescape/backend/pkg/client/v1"
	"github.com/kubescape/backend/pkg/servicediscovery"
	servicediscoveryv1 "github.com/kubescape/backend/pkg/servicediscovery/v1"
	"github.com/kubescape/backend/pkg/utils"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/go-logger/zaplogger"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
	"github.com/kubescape/kubescape/v2/httphandler/config"
	_ "github.com/kubescape/kubescape/v2/httphandler/docs"
	"github.com/kubescape/kubescape/v2/httphandler/listener"
	"github.com/kubescape/kubescape/v2/httphandler/storage"
	"k8s.io/client-go/rest"
)

const (
	defaultNamespace = "kubescape"
)

func main() {
	ctx := context.Background()

	loadAndSetTokenAndAccountId()

	// to enable otel, set OTEL_COLLECTOR_SVC=otel-collector:4317
	if otelHost, present := os.LookupEnv("OTEL_COLLECTOR_SVC"); present {
		ctx = logger.InitOtel("kubescape",
			os.Getenv(cautils.BuildNumber),
			config.GetAccount(),
			os.Getenv("CLUSTER_NAME"),
			url.URL{Host: otelHost})
		defer logger.ShutdownOtel(ctx)
	}

	logger.L().Debug("setting cluster context name", helpers.String("context", os.Getenv("KS_CONTEXT")))
	k8sinterface.SetClusterContextName(os.Getenv("KS_CONTEXT"))

	initializeLoggerName()
	initializeLoggerLevel()
	initializeSaaSEnv()
	initializeStorage()

	// traces will be created by otelmux.Middleware in SetupHTTPListener()

	logger.L().Ctx(ctx).Fatal(listener.SetupHTTPListener().Error())
}

func initializeStorage() {
	if !cautils.GetTenantConfig("", "", "", nil).IsStorageEnabled() {
		logger.L().Debug("storage disabled - skipping initialization")
		return
	}

	namespace := getNamespace()
	logger.L().Debug("storage enabled", helpers.String("namespace", namespace))

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

	s, err := storage.NewAPIServerStorage(namespace, config)
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
		servicediscoveryv1.NewServiceDiscoveryFileV1(serviceDiscoveryFilePath),
	)
	if err != nil {
		logger.L().Fatal("failed to get backend services", helpers.Error(err))
		return
	}

	if ksCloud, err := v1.NewKSCloudAPI(backendServices.GetReportReceiverHttpUrl(), backendServices.GetApiServerUrl(), config.GetAccount(), config.GetAccessToken()); err != nil {
		logger.L().Fatal("failed to initialize cloud api", helpers.Error(err))
	} else {
		getter.SetKSCloudAPIConnector(ksCloud)
	}
}

func getNamespace() string {
	if ns, ok := os.LookupEnv("NAMESPACE"); ok {
		return ns
	}
	return defaultNamespace
}

func loadAndSetTokenAndAccountId() {
	tokenSecretPath := "/etc/access-token-secret"
	if envVar := os.Getenv("KS_TOKEN_SECRET_PATH"); envVar != "" {
		tokenSecretPath = envVar
	}

	sd, err := utils.LoadTokenFromFile(tokenSecretPath)
	if err != nil {
		logger.L().Fatal("failed to load access token", helpers.Error(err))
	}

	if sd.Token != "" {
		logger.L().Debug("access token loaded from path", helpers.String("path", tokenSecretPath))
		config.SetAccessToken(sd.Token)
	}
	if sd.Account != "" {
		logger.L().Debug("account loaded from file path", helpers.String("path", tokenSecretPath))
		config.SetAccount(sd.Account)
	}
}
