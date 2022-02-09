package cmd

import (
	"fmt"

	"github.com/armosec/kubescape/cautils/logger"
	"github.com/armosec/kubescape/clihandler"
	"github.com/armosec/kubescape/clihandler/cliobjects"
	"github.com/spf13/cobra"
)

var submitInfo cliobjects.Submit

var submitCmdExamples = `

`
var submitCmd = &cobra.Command{
	Use:   "submit <command>",
	Short: "Submit an object to the Kubescape SaaS version",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

var submitExceptionsCmd = &cobra.Command{
	Use:   "exceptions <full path to exceptins file>",
	Short: "Submit exceptions to the Kubescape SaaS version",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("missing full path to exceptions file")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		if err := clihandler.SubmitExceptions(submitInfo.Account, args[0]); err != nil {
			logger.L().Fatal(err.Error())
		}
	},
}

func init() {
	submitCmd.PersistentFlags().StringVarP(&submitInfo.Account, "account", "", "", "Armo portal account ID. Default will load account ID from configMap or config file")
	rootCmd.AddCommand(submitCmd)

	submitCmd.AddCommand(submitExceptionsCmd)
}
