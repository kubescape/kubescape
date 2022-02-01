package cmd

import (
	"fmt"
	"os"

	"github.com/armosec/kubescape/clihandler"
	"github.com/spf13/cobra"
)

// configCmd represents the config command
var viewCmd = &cobra.Command{
	Use:   "view",
	Short: "View configurations and other data",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

// configCmd represents the config command
var viewConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "View cached configurations",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if err := clihandler.CliView(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(viewCmd)
	viewCmd.AddCommand(viewConfigCmd)
}
