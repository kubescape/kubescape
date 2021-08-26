package cmd

import (
	"github.com/spf13/cobra"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "kubescape",
	Short: "A tool for running NSA recommended tests in your cluster ",
	Long: `Kubescape is the first tool for testing if Kubernetes is deployed securely as defined in Kubernetes Hardening Guidance
by to NSA and CISA Tests are configured with YAML files, making this tool easy to update as test specifications evolve.`,
}

func Execute() {
	rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
}
