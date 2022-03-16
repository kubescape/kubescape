package main

import (
	"fmt"
	"strings"

	"github.com/armosec/kubescape/cmd/completion"
	"github.com/armosec/kubescape/cmd/config"
	"github.com/armosec/kubescape/cmd/delete"
	"github.com/armosec/kubescape/cmd/download"
	"github.com/armosec/kubescape/cmd/list"
	"github.com/armosec/kubescape/cmd/scan"
	"github.com/armosec/kubescape/cmd/submit"
	"github.com/armosec/kubescape/cmd/version"
	"github.com/armosec/kubescape/core/cautils"
	"github.com/armosec/kubescape/core/cautils/getter"
	"github.com/armosec/kubescape/core/cautils/logger"
	"github.com/armosec/kubescape/core/cautils/logger/helpers"
	"github.com/armosec/kubescape/core/core"
	"github.com/armosec/kubescape/core/meta"

	"github.com/spf13/cobra"
)

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
	var rootInfo cautils.RootInfo

	rootCmd := &cobra.Command{
		Use:     "kubescape",
		Version: cautils.BuildNumber,
		Short:   "Kubescape is a tool for testing Kubernetes security posture",
		Long:    `Based on NSA \ MITRE ATT&CK® and other frameworks specifications`,
		Example: ksExamples,
	}

	rootCmd.PersistentFlags().StringVar(&armoBEURLsDep, "environment", "", envFlagUsage)
	rootCmd.PersistentFlags().StringVar(&armoBEURLs, "env", "", envFlagUsage)
	rootCmd.PersistentFlags().MarkDeprecated("environment", "use 'env' instead")
	rootCmd.PersistentFlags().MarkHidden("environment")
	rootCmd.PersistentFlags().MarkHidden("env")

	rootCmd.PersistentFlags().StringVar(&rootInfo.LoggerName, "logger-name", "", fmt.Sprintf("Logger name. Supported: %s [$KS_LOGGER_NAME]", strings.Join(logger.ListLoggersNames(), "/")))
	rootCmd.PersistentFlags().MarkHidden("logger-name")

	rootCmd.PersistentFlags().StringVarP(&rootInfo.Logger, "logger", "l", helpers.InfoLevel.String(), fmt.Sprintf("Logger level. Supported: %s [$KS_LOGGER]", strings.Join(helpers.SupportedLevels(), "/")))
	rootCmd.PersistentFlags().StringVar(&rootInfo.CacheDir, "cache-dir", getter.DefaultLocalStore, "Cache directory [$KS_CACHE_DIR]")
	rootCmd.PersistentFlags().BoolVarP(&rootInfo.DisableColor, "disable-color", "", false, "Disable Color output for logging")

	// Initialize
	initLogger(&rootInfo)
	initLoggerLevel(&rootInfo)
	initEnvironment(&rootInfo)
	initCacheDir(&rootInfo)

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

func main() {
	ks := NewDefaultKubescapeCommand()
	ks.Execute()
}
