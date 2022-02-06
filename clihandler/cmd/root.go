package cmd

import (
	"flag"
	"fmt"
	"strings"

	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/kubescape/cautils/logger"
	"github.com/armosec/kubescape/cautils/logger/helpers"
	"github.com/spf13/cobra"
)

var armoBEURLs = ""

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
	Short:   "Kubescape is a tool for testing Kubernetes security posture",
	Long:    `Kubescape is a tool for testing Kubernetes security posture based on NSA \ MITRE ATT&CK® and other frameworks specifications`,
	Example: ksExamples,
}

func Execute() {
	rootCmd.Execute()
}
func init() {
	cobra.OnInitialize(initLogger, initEnvironment)

	flag.CommandLine.StringVar(&armoBEURLs, "environment", "", envFlagUsage)
	rootCmd.PersistentFlags().StringVar(&armoBEURLs, "environment", "", envFlagUsage)
	rootCmd.PersistentFlags().MarkHidden("environment")
	rootCmd.PersistentFlags().StringVar(&scanInfo.Logger, "logger", "info", fmt.Sprintf("Logger level. Supported: %s", strings.Join(helpers.SupportedLevels(), "/")))
	flag.Parse()
}

func initLogger() {
	if err := logger.L().SetLevel(scanInfo.Logger); err != nil {
		logger.L().Fatal(fmt.Sprintf("supported levels: %s", strings.Join(helpers.SupportedLevels(), "/")), helpers.Error(err))
	}
}
func initEnvironment() {
	urlSlices := strings.Split(armoBEURLs, ",")
	if len(urlSlices) > 3 {
		logger.L().Fatal("expected only 3 URLs")
	}
	switch len(urlSlices) {
	case 1:
		switch urlSlices[0] {
		case "dev":
			getter.SetARMOAPIConnector(getter.NewARMOAPIDev())
		case "":
			getter.SetARMOAPIConnector(getter.NewARMOAPIProd())
		default:
			logger.L().Fatal("--environment flag usage: " + envFlagUsage)
		}
	case 2:
		logger.L().Fatal("--environment flag usage: " + envFlagUsage)
	case 3:
		getter.SetARMOAPIConnector(getter.NewARMOAPICustomized(urlSlices[0], urlSlices[1], urlSlices[2]))
	}
}
