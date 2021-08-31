package cmd

import (
	"github.com/spf13/cobra"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "kubescape",
	Short: "Kubescape is a tool for testing Kubernetes security posture",
	Long:  `Kubescape is a tool for testing Kubernetes security posture based on NSA specifications.`,
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
