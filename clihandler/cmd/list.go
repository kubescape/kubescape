package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/clihandler"
	"github.com/spf13/cobra"
)

var (
	listExample = `
  # List default supported frameworks names
  kubescape list frameworks
  
  # List all supported frameworks names
  kubescape list frameworks --account <account id>
	
  # List all supported controls names
  kubescape list controls

  # List all supported controls ids
  kubescape list controls --id 
  
  Control documentation:
  https://hub.armo.cloud/docs/controls
`
)
var listPolicies = cautils.ListPolicies{}

var listCmd = &cobra.Command{
	Use:     "list <policy> [flags]",
	Short:   "List frameworks/controls will list the supported frameworks and controls",
	Long:    ``,
	Example: listExample,
	Args: func(cmd *cobra.Command, args []string) error {
		supported := strings.Join(clihandler.ListSupportCommands(), ",")

		if len(args) < 1 {
			return fmt.Errorf("policy type requeued, supported: %s", supported)
		}
		if cautils.StringInSlice(clihandler.ListSupportCommands(), args[0]) == cautils.ValueNotFound {
			return fmt.Errorf("invalid parameter '%s'. Supported parameters: %s", args[0], supported)
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		listPolicies.Target = args[0]

		if err := clihandler.CliList(&listPolicies); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	// cobra.OnInitialize(initConfig)

	rootCmd.AddCommand(listCmd)
	listCmd.PersistentFlags().StringVarP(&listPolicies.Account, "account", "", "", "Armo portal account ID. Default will load account ID from configMap or config file")
	listCmd.PersistentFlags().BoolVarP(&listPolicies.ListIDs, "id", "", false, "List control ID's instead of controls names")
}
