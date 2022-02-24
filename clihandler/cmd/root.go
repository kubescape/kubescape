package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/kubescape/cautils/logger"
	"github.com/armosec/kubescape/cautils/logger/helpers"
	"github.com/spf13/cobra"
)

var armoBEURLs = ""
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

	cobra.OnInitialize(initLogger, initLoggerLevel, initEnvironment, initCacheDir)

	rootCmd.PersistentFlags().StringVar(&armoBEURLs, "environment", "", envFlagUsage)
	rootCmd.PersistentFlags().MarkHidden("environment")
	rootCmd.PersistentFlags().StringVarP(&rootInfo.Logger, "logger", "l", helpers.InfoLevel.String(), fmt.Sprintf("Logger level. Supported: %s [$KS_LOGGER]", strings.Join(helpers.SupportedLevels(), "/")))
	rootCmd.PersistentFlags().StringVar(&rootInfo.CacheDir, "cache-dir", getter.DefaultLocalStore, "Cache directory [$KS_CACHE_DIR]")
}

func initLogger() {
	if l := os.Getenv("KS_LOGGER_NAME"); l != "" {
		logger.InitializeLogger(l)
	}
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
	if rootInfo.CacheDir != getter.DefaultLocalStore {
		getter.DefaultLocalStore = rootInfo.CacheDir
	} else if cacheDir := os.Getenv("KS_CACHE_DIR"); cacheDir != "" {
		getter.DefaultLocalStore = cacheDir
	} else {
		return // using default cache di location
	}

	logger.L().Debug("cache dir updated", helpers.String("path", getter.DefaultLocalStore))
}
func initEnvironment() {
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
