package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	v1 "github.com/kubescape/backend/pkg/client/v1"
	"github.com/kubescape/backend/pkg/servicediscovery"
	sdClientV2 "github.com/kubescape/backend/pkg/servicediscovery/v2"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/go-logger/iconlogger"
	"github.com/kubescape/go-logger/zaplogger"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

var isTerminal = isatty.IsTerminal

func initLogger() {
	if rootInfo.LoggerName == "" {
		if l := os.Getenv("KS_LOGGER_NAME"); l != "" {
			rootInfo.LoggerName = l
		} else {
			if isTerminal(os.Stdout.Fd()) {
				rootInfo.LoggerName = iconlogger.LoggerName
			} else {
				rootInfo.LoggerName = zaplogger.LoggerName
			}
		}
	}

	logger.InitLogger(rootInfo.LoggerName)
}

func initLoggerLevel(cmd *cobra.Command) error {
	loggerExplicit := false
	if cmd != nil {
		// Persistent flags are parsed on the root while traversing to the subcommand.
		// cmd.Flag("logger") on a child can be a merged copy that never gets Changed=true;
		// the root flag holds the authoritative parse state (see cobra Traverse + ParseFlags).
		r := cmd.Root()
		if lf := r.Flag("logger"); lf != nil {
			loggerExplicit = lf.Changed
		} else if lf := cmd.Flag("logger"); lf != nil {
			loggerExplicit = lf.Changed
		}
	}
	if !loggerExplicit && rootInfo.Logger == helpers.InfoLevel.String() {
		if l := os.Getenv("KS_LOGGER"); l != "" {
			rootInfo.Logger = l
		}
	}

	if err := logger.L().SetLevel(rootInfo.Logger); err != nil {
		return fmt.Errorf("supported levels: %s: %w", strings.Join(helpers.SupportedLevels(), "/"), err)
	}
	return nil
}

func initCacheDir(cmd *cobra.Command) {
	cacheDirExplicit := false
	if cmd != nil {
		// Persistent flags are parsed on the root while traversing to the subcommand.
		// cmd.Flag("cache-dir") on a child can be a merged copy that never gets Changed=true;
		// the root flag holds the authoritative parse state (see cobra Traverse + ParseFlags).
		r := cmd.Root()
		if f := r.Flag("cache-dir"); f != nil {
			cacheDirExplicit = f.Changed
		} else if f := cmd.Flag("cache-dir"); f != nil {
			cacheDirExplicit = f.Changed
		}
	}
	if !cacheDirExplicit {
		if cacheDir := os.Getenv("KS_CACHE_DIR"); cacheDir != "" {
			getter.DefaultLocalStore = cacheDir
			logger.L().Debug("cache dir updated", helpers.String("path", getter.DefaultLocalStore))
		}
	} else {
		getter.DefaultLocalStore = rootInfo.CacheDir
		logger.L().Debug("cache dir updated", helpers.String("path", getter.DefaultLocalStore))
	}
}
func initEnvironment(ctx context.Context) error {
	if rootInfo.DiscoveryServerURL == "" {
		return nil
	}

	logger.L().Debug("fetching URLs from service discovery server", helpers.String("server", rootInfo.DiscoveryServerURL))

	client, err := sdClientV2.NewServiceDiscoveryClientV2(rootInfo.DiscoveryServerURL)
	if err != nil {
		return fmt.Errorf("failed to create service discovery client for %q: %w", rootInfo.DiscoveryServerURL, err)
	}

	services, err := servicediscovery.GetServices(
		client,
	)

	if err != nil {
		return fmt.Errorf("failed to get services from server %q: %w", rootInfo.DiscoveryServerURL, err)
	}

	logger.L().Debug("configuring service discovery URLs", helpers.String("cloudAPIURL", services.GetApiServerUrl()), helpers.String("cloudReportURL", services.GetReportReceiverHttpUrl()))

	tenant := cautils.GetTenantConfig(ctx, "", "", "", "", nil)
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
		return fmt.Errorf("failed to create KS Cloud client: %w", err)
	}

	getter.SetKSCloudAPIConnector(ksCloud)
	return nil
}
