package cmd

import (
	"fmt"
	"os"

	"github.com/armosec/kubescape/clihandler"
	"github.com/armosec/kubescape/clihandler/cliobjects"
	"github.com/spf13/cobra"
)

var (
	setConfigExample = `
  # Set account credentials
  kubescape set config --account <account id> --client-id <client id> --access-key <access key>
`
)
var setConfig = cliobjects.SetConfig{}

// configCmd represents the config command
var setCmd = &cobra.Command{
	Use:     "set",
	Short:   "Set configurations and other data",
	Long:    ``,
	Example: setConfigExample,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

// configCmd represents the config command
var setConfigCmd = &cobra.Command{
	Use:     "config",
	Short:   "Set cached configurations",
	Long:    ``,
	Example: setConfigExample,
	Run: func(cmd *cobra.Command, args []string) {
		if err := clihandler.CliSetConfig(&setConfig); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {

	setConfigCmd.PersistentFlags().StringVarP(&setConfig.Account, "account", "", "", "Set Armo account ID")
	setConfigCmd.PersistentFlags().StringVarP(&setConfig.ClientID, "client-id", "", "", "Set Armo client ID")
	setConfigCmd.PersistentFlags().StringVarP(&setConfig.AccessKey, "access-key", "", "", "Set Armo access key")

	rootCmd.AddCommand(setCmd)
	setCmd.AddCommand(setConfigCmd)

}
