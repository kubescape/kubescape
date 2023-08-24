package cmd

import (
	"fmt"
	"os"
	"strings"

	v1 "github.com/kubescape/backend/pkg/client/v1"
	"github.com/kubescape/backend/pkg/servicediscovery"
	sdClientV1 "github.com/kubescape/backend/pkg/servicediscovery/v1"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"

	"github.com/mattn/go-isatty"
)

func initLogger() {
	logger.DisableColor(rootInfo.DisableColor)
	logger.EnableColor(rootInfo.EnableColor)

	if rootInfo.LoggerName == "" {
		if l := os.Getenv("KS_LOGGER_NAME"); l != "" {
			rootInfo.LoggerName = l
		} else {
			if isatty.IsTerminal(os.Stdout.Fd()) {
				rootInfo.LoggerName = "pretty"
			} else {
				rootInfo.LoggerName = "zap"
			}
		}
	}

	logger.InitLogger(rootInfo.LoggerName)

}
func initLoggerLevel() {
	if rootInfo.Logger == helpers.InfoLevel.String() {
	} else if l := os.Getenv("KS_LOGGER"); l != "" {
		rootInfo.Logger = l
	}

	if err := logger.L().SetLevel(rootInfo.Logger); err != nil {
		logger.L().Fatal(fmt.Sprintf("supported levels: %s", strings.Join(helpers.SupportedLevels(), "/")), helpers.Error(err))
	}
}

func initCacheDir() {
	if rootInfo.CacheDir != getter.DefaultLocalStore {
		getter.DefaultLocalStore = rootInfo.CacheDir
	} else if cacheDir := os.Getenv("KS_CACHE_DIR"); cacheDir != "" {
		getter.DefaultLocalStore = cacheDir
	} else {
		return // using default cache dir location
	}

	logger.L().Debug("cache dir updated", helpers.String("path", getter.DefaultLocalStore))
}
func initEnvironment() {
	if rootInfo.DiscoveryServerURL == "" {
		return
	}

	client, err := sdClientV1.NewServiceDiscoveryClientV1(rootInfo.DiscoveryServerURL)
	if err != nil {
		logger.L().Fatal("failed to create service discovery client", helpers.Error(err), helpers.String("server", rootInfo.DiscoveryServerURL))
		return
	}

	services, err := servicediscovery.GetServices(
		client,
	)

	if err != nil {
		logger.L().Fatal("failed to to get services from server", helpers.Error(err), helpers.String("server", rootInfo.DiscoveryServerURL))
		return
	}

	logger.L().Info("configured backend", helpers.String("cloudAPIURL", services.GetApiServerUrl()), helpers.String("cloudReportURL", services.GetReportReceiverHttpUrl()))

	ksCloud, err := v1.NewKSCloudAPI(
		services.GetApiServerUrl(),
		services.GetReportReceiverHttpUrl(),
		"",
	)
	if err != nil {
		logger.L().Fatal("failed to create KS Cloud client", helpers.Error(err))
		return
	}

	getter.SetKSCloudAPIConnector(ksCloud)

	// // we would like to update the cached config
	// tenantConfig := cautils.GetTenantConfigWithBackend("", "", "", nil, ksCloud)
	// tenantConfig.UpdateCachedConfig()
}
