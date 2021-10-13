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

var rootCmd = &cobra.Command{
	Use:   "kubescape",
	Short: "Kubescape is a tool for testing Kubernetes security posture",
	Long:  `Kubescape is a tool for testing Kubernetes security posture based on NSA \ MITRE ATT&CK® specifications.`,
}

func Execute() {
	rootCmd.Execute()
}

func init() {
	flag.CommandLine.StringVar(&armoBEURLs, "environment", "", envFlagUsage)
	rootCmd.PersistentFlags().StringVar(&armoBEURLs, "environment", "", envFlagUsage)
	rootCmd.PersistentFlags().MarkHidden("environment")
	cobra.OnInitialize(initConfig)

}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
}

func InitArmoBEConnector() {
	if armoBEURLs == "" && rootCmd.Flag("environment") != nil {
		armoBEURLs = rootCmd.Flag("environment").Value.String()
	}
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
