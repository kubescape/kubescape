package cmd

import (
	"flag"
	"os"
	"strings"

	"github.com/armosec/kubescape/cautils/getter"
	"github.com/golang/glog"
	"github.com/spf13/cobra"
)

var cfgFile string
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
	rootCmd.PersistentFlags().StringVarP(&scanInfo.Account, "account", "", "", "Armo portal account ID. Default will load account ID from configMap or config file")
	flag.CommandLine.StringVar(&armoBEURLs, "environment", "", envFlagUsage)
	rootCmd.PersistentFlags().StringVar(&armoBEURLs, "environment", "", envFlagUsage)
	rootCmd.PersistentFlags().MarkHidden("environment")

}

func InitArmoBEConnector() {
	urlSlices := strings.Split(armoBEURLs, ",")
	if len(urlSlices) > 3 {
		glog.Errorf("Too many URLs")
		os.Exit(1)
	}
	switch len(urlSlices) {
	case 1:
		switch urlSlices[0] {
		case "dev":
			getter.SetARMOAPIConnector(getter.NewARMOAPIDev())
		case "":
			getter.SetARMOAPIConnector(getter.NewARMOAPIProd())
		default:
			glog.Errorf("--environment flag usage: %s", envFlagUsage)
			os.Exit(1)
		}
	case 2:
		glog.Errorf("--environment flag usage: %s", envFlagUsage)
		os.Exit(1)
	case 3:
		getter.SetARMOAPIConnector(getter.NewARMOAPICustomized(urlSlices[0], urlSlices[1], urlSlices[2]))
	}
}
