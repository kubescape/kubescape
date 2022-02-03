package cmd

import (
	"flag"
	"strings"

	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/kubescape/cautils/logger"
	"github.com/spf13/cobra"
)

var armoBEURLs = ""

const envFlagUsage = "Send report results to specific URL. Format:<ReportReceiver>,<Backend>,<Frontend>.\n\t\tExample:report.armo.cloud,api.armo.cloud,portal.armo.cloud"

var rootCmd = &cobra.Command{
	Use:   "kubescape",
	Short: "Kubescape is a tool for testing Kubernetes security posture",
	Long:  `Kubescape is a tool for testing Kubernetes security posture based on NSA \ MITRE ATT&CK® specifications.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		flag.Parse()
		InitArmoBEConnector()
		return nil
	},
}

func Execute() {
	rootCmd.Execute()
}

func init() {

	flag.CommandLine.StringVar(&armoBEURLs, "environment", "", envFlagUsage)
	rootCmd.PersistentFlags().StringVar(&armoBEURLs, "environment", "", envFlagUsage)
	rootCmd.PersistentFlags().MarkHidden("environment")

}

func InitArmoBEConnector() {
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
