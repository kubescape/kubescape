package cmd

import (
	"fmt"
	"strings"

	"github.com/armosec/kubescape/cautils/logger"
	"github.com/armosec/kubescape/clihandler"
	"github.com/armosec/kubescape/clihandler/cliobjects"
	"github.com/spf13/cobra"
)

var deleteInfo cliobjects.Delete

var deleteExceptionsExamples = `
  # Delete single exception
  kubescape delete exceptions "exception name"

  # Delete multiple exceptions
  kubescape delete exceptions "first exception;second exception;third exception"
`

var deleteCmd = &cobra.Command{
	Use:   "delete <command>",
	Short: "Delete configurations in Kubescape SaaS version",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

var deleteExceptionsCmd = &cobra.Command{
	Use:     "exceptions <exception name>",
	Short:   "Delete exceptions from Kubescape SaaS version. Run 'kubescape list exceptions' for all exceptions names",
	Example: deleteExceptionsExamples,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("missing exceptions names")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		exceptionsNames := strings.Split(args[0], ";")
		if len(exceptionsNames) == 0 {
			logger.L().Fatal("missing exceptions names")
		}
		if err := clihandler.DeleteExceptions(deleteInfo.Account, exceptionsNames); err != nil {
			logger.L().Fatal(err.Error())
		}
	},
}

func init() {
	deleteCmd.PersistentFlags().StringVarP(&deleteInfo.Account, "account", "", "", "Armo portal account ID. Default will load account ID from configMap or config file")
	rootCmd.AddCommand(deleteCmd)

	deleteCmd.AddCommand(deleteExceptionsCmd)
}
