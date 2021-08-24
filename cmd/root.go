package cmd

import (
	"github.com/spf13/cobra"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "kubescape",
	Short: "A tool for running NSA recommended tests in your cluster ",
	Long: `This tool pulls checks based on the NSA recommendations from the ARMO backend
	and run these checks on your cluster resources `,
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
