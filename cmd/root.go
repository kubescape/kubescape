package cmd

import (
	"fmt"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v2/cmd/completion"
	"github.com/kubescape/kubescape/v2/cmd/config"
	"github.com/kubescape/kubescape/v2/cmd/delete"
	"github.com/kubescape/kubescape/v2/cmd/download"
	"github.com/kubescape/kubescape/v2/cmd/list"
	"github.com/kubescape/kubescape/v2/cmd/scan"
	"github.com/kubescape/kubescape/v2/cmd/submit"
	"github.com/kubescape/kubescape/v2/cmd/version"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
	"github.com/kubescape/kubescape/v2/core/core"
	"github.com/kubescape/kubescape/v2/core/meta"

	"github.com/spf13/cobra"
)

var rootInfo cautils.RootInfo

var ksExamples = `
  # Scan command
  kubescape scan --submit

  # List supported frameworks
  kubescape list frameworks

  # Download artifacts (air-gapped environment support)
  kubescape download artifacts

  # View cached configurations
  kubescape config view
`

func NewDefaultKubescapeCommand() *cobra.Command {
	ks := core.NewKubescape()
	return getRootCmd(ks)
}

func getRootCmd(ks meta.IKubescape) *cobra.Command {

	rootCmd := &cobra.Command{
		Use:     "kubescape",
		Short:   "Kubescape is a tool for testing Kubernetes security posture. Docs: https://hub.armosec.io/docs",
		Example: ksExamples,
	}

	rootCmd.PersistentFlags().StringVar(&rootInfo.KSCloudBEURLsDep, "environment", "", envFlagUsage)
	rootCmd.PersistentFlags().StringVar(&rootInfo.KSCloudBEURLs, "env", "", envFlagUsage)
	rootCmd.PersistentFlags().MarkDeprecated("environment", "use 'env' instead")
	rootCmd.PersistentFlags().MarkHidden("environment")
	rootCmd.PersistentFlags().MarkHidden("env")

	rootCmd.PersistentFlags().StringVar(&rootInfo.LoggerName, "logger-name", "", fmt.Sprintf("Logger name. Supported: %s [$KS_LOGGER_NAME]", strings.Join(logger.ListLoggersNames(), "/")))
	rootCmd.PersistentFlags().MarkHidden("logger-name")

	rootCmd.PersistentFlags().StringVarP(&rootInfo.Logger, "logger", "l", helpers.InfoLevel.String(), fmt.Sprintf("Logger level. Supported: %s [$KS_LOGGER]", strings.Join(helpers.SupportedLevels(), "/")))
	rootCmd.PersistentFlags().StringVar(&rootInfo.CacheDir, "cache-dir", getter.DefaultLocalStore, "Cache directory [$KS_CACHE_DIR]")
	rootCmd.PersistentFlags().BoolVarP(&rootInfo.DisableColor, "disable-color", "", false, "Disable Color output for logging")
	rootCmd.PersistentFlags().BoolVarP(&rootInfo.EnableColor, "enable-color", "", false, "Force enable Color output for logging")

	cobra.OnInitialize(initLogger, initLoggerLevel, initEnvironment, initCacheDir)

	// Supported commands
	rootCmd.AddCommand(scan.GetScanCommand(ks))
	rootCmd.AddCommand(download.GeDownloadCmd(ks))
	rootCmd.AddCommand(delete.GetDeleteCmd(ks))
	rootCmd.AddCommand(list.GetListCmd(ks))
	rootCmd.AddCommand(submit.GetSubmitCmd(ks))
	rootCmd.AddCommand(completion.GetCompletionCmd())
	rootCmd.AddCommand(version.GetVersionCmd())
	rootCmd.AddCommand(config.GetConfigCmd(ks))

	return rootCmd
}

func Execute() error {
	ks := NewDefaultKubescapeCommand()
	return ks.Execute()
}
