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
	"github.com/kubescape/kubescape/v2/cmd/fix"
	"github.com/kubescape/kubescape/v2/cmd/list"
	"github.com/kubescape/kubescape/v2/cmd/patch"
	"github.com/kubescape/kubescape/v2/cmd/scan"
	"github.com/kubescape/kubescape/v2/cmd/submit"
	"github.com/kubescape/kubescape/v2/cmd/update"
	"github.com/kubescape/kubescape/v2/cmd/version"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
	"github.com/kubescape/kubescape/v2/core/core"
	"github.com/kubescape/kubescape/v2/core/meta"

	"github.com/spf13/cobra"
)

var rootInfo cautils.RootInfo

var ksExamples = fmt.Sprintf(`
  # Scan command
  %[1]s scan

  # List supported frameworks
  %[1]s list frameworks

  # Download artifacts (air-gapped environment support)
  %[1]s download artifacts

  # View cached configurations
  %[1]s config view
`, cautils.ExecName())

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

	if cautils.IsKrewPlugin() {
		// Invoked as a kubectl plugin.

		// Cobra doesn't have a way to specify a two word command (i.e. "kubectl kubescape"), so set a custom usage template
		// with kubectl in it. Cobra will use this template for the root and all child commands.
		oldUsageTemplate := rootCmd.UsageTemplate()
		newUsageTemplate := strings.NewReplacer("{{.UseLine}}", "kubectl {{.UseLine}}", "{{.CommandPath}}", "kubectl {{.CommandPath}}").Replace(oldUsageTemplate)
		rootCmd.SetUsageTemplate(newUsageTemplate)
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
	rootCmd.AddCommand(download.GetDownloadCmd(ks))
	rootCmd.AddCommand(delete.GetDeleteCmd(ks))
	rootCmd.AddCommand(list.GetListCmd(ks))
	rootCmd.AddCommand(submit.GetSubmitCmd(ks))
	rootCmd.AddCommand(completion.GetCompletionCmd())
	rootCmd.AddCommand(version.GetVersionCmd())
	rootCmd.AddCommand(config.GetConfigCmd(ks))
	rootCmd.AddCommand(update.GetUpdateCmd())
	rootCmd.AddCommand(fix.GetFixCmd(ks))
	rootCmd.AddCommand(patch.GetPatchCmd(ks))

	return rootCmd
}

func Execute() error {
	ks := NewDefaultKubescapeCommand()
	return ks.Execute()
}
