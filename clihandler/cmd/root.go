package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/kubescape/cautils/logger"
	"github.com/armosec/kubescape/cautils/logger/helpers"
	"github.com/armosec/kubescape/clihandler/cmd/completion"
	"github.com/armosec/kubescape/clihandler/cmd/config"
	"github.com/armosec/kubescape/clihandler/cmd/delete"
	"github.com/armosec/kubescape/clihandler/cmd/download"
	"github.com/armosec/kubescape/clihandler/cmd/list"
	"github.com/armosec/kubescape/clihandler/cmd/scan"
	"github.com/armosec/kubescape/clihandler/cmd/submit"
	"github.com/armosec/kubescape/clihandler/cmd/version"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

var armoBEURLs = ""
var armoBEURLsDep = ""
var rootInfo cautils.RootInfo

const envFlagUsage = "Send report results to specific URL. Format:<ReportReceiver>,<Backend>,<Frontend>.\n\t\tExample:report.armo.cloud,api.armo.cloud,portal.armo.cloud"

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

var rootCmd = &cobra.Command{
	Use:     "kubescape",
	Version: cautils.BuildNumber,
	Short:   "Kubescape is a tool for testing Kubernetes security posture",
	Long:    `Based on NSA \ MITRE ATT&CK® and other frameworks specifications`,
	Example: ksExamples,
}

func Execute() {
	rootCmd.Execute()
}

func init() {

	rootCmd.AddCommand(scan.GetScanCommand())
	rootCmd.AddCommand(download.GeDownloadCmd())
	rootCmd.AddCommand(delete.GetDeleteCmd())
	rootCmd.AddCommand(list.GetListCmd())
	rootCmd.AddCommand(submit.GetSubmitCmd())
	rootCmd.AddCommand(completion.GetCompletionCmd())
	rootCmd.AddCommand(version.GetVersionCmd())
	rootCmd.AddCommand(config.GetConfigCmd())

	cobra.OnInitialize(initLogger, initLoggerLevel, initEnvironment, initCacheDir)

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

}

func initLogger() {
	logger.DisableColor(rootInfo.DisableColor)

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
	if rootInfo.Logger != helpers.InfoLevel.String() {
	} else if l := os.Getenv("KS_LOGGER"); l != "" {
		rootInfo.Logger = l
	}

	if err := logger.L().SetLevel(rootInfo.Logger); err != nil {
		logger.L().Fatal(fmt.Sprintf("supported levels: %s", strings.Join(helpers.SupportedLevels(), "/")), helpers.Error(err))
	}
}

func initCacheDir() {
	if rootInfo.CacheDir == getter.DefaultLocalStore {
		getter.DefaultLocalStore = rootInfo.CacheDir
	} else if cacheDir := os.Getenv("KS_CACHE_DIR"); cacheDir != "" {
		getter.DefaultLocalStore = cacheDir
	} else {
		return // using default cache dir location
	}

	logger.L().Debug("cache dir updated", helpers.String("path", getter.DefaultLocalStore))
}
func initEnvironment() {
	if armoBEURLsDep != "" {
		armoBEURLs = armoBEURLsDep
	}
	urlSlices := strings.Split(armoBEURLs, ",")
	if len(urlSlices) != 1 && len(urlSlices) < 3 {
		logger.L().Fatal("expected at least 3 URLs (report, api, frontend, auth)")
	}
	switch len(urlSlices) {
	case 1:
		switch urlSlices[0] {
		case "dev", "development":
			getter.SetARMOAPIConnector(getter.NewARMOAPIDev())
		case "stage", "staging":
			getter.SetARMOAPIConnector(getter.NewARMOAPIStaging())
		case "":
			getter.SetARMOAPIConnector(getter.NewARMOAPIProd())
		default:
			logger.L().Fatal("--environment flag usage: " + envFlagUsage)
		}
	case 2:
		logger.L().Fatal("--environment flag usage: " + envFlagUsage)
	case 3, 4:
		var armoAUTHURL string
		armoERURL := urlSlices[0] // mandatory
		armoBEURL := urlSlices[1] // mandatory
		armoFEURL := urlSlices[2] // mandatory
		if len(urlSlices) <= 4 {
			armoAUTHURL = urlSlices[3]
		}
		getter.SetARMOAPIConnector(getter.NewARMOAPICustomized(armoERURL, armoBEURL, armoFEURL, armoAUTHURL))
	}
}
