package cmd

import (
	"fmt"
	"os"
	"strings"

	v1 "github.com/kubescape/backend/pkg/client/v1"
	"github.com/kubescape/backend/pkg/servicediscovery"
	sdClientV2 "github.com/kubescape/backend/pkg/servicediscovery/v2"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/go-logger/iconlogger"
	"github.com/kubescape/go-logger/zaplogger"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"

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
				rootInfo.LoggerName = iconlogger.LoggerName
			} else {
				rootInfo.LoggerName = zaplogger.LoggerName
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

	logger.L().Debug("fetching URLs from service discovery server", helpers.String("server", rootInfo.DiscoveryServerURL))

	client, err := sdClientV2.NewServiceDiscoveryClientV2(rootInfo.DiscoveryServerURL)
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

	logger.L().Debug("configuring service discovery URLs", helpers.String("cloudAPIURL", services.GetApiServerUrl()), helpers.String("cloudReportURL", services.GetReportReceiverHttpUrl()))

	tenant := cautils.GetTenantConfig("", "", "", "", nil)
	if services.GetApiServerUrl() != "" {
		tenant.GetConfigObj().CloudAPIURL = services.GetApiServerUrl()
	}
	if services.GetReportReceiverHttpUrl() != "" {
		tenant.GetConfigObj().CloudReportURL = services.GetReportReceiverHttpUrl()
	}

	if err = tenant.UpdateCachedConfig(); err != nil {
		logger.L().Error("failed to update cached config", helpers.Error(err))
	}

	ksCloud, err := v1.NewKSCloudAPI(
		services.GetApiServerUrl(),
		services.GetReportReceiverHttpUrl(),
		"",
		"",
	)
	if err != nil {
		logger.L().Fatal("failed to create KS Cloud client", helpers.Error(err))
		return
	}

	getter.SetKSCloudAPIConnector(ksCloud)
}
