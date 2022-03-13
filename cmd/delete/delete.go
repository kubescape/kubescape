package delete

import (
	"github.com/armosec/kubescape/core/metadata/cliobjects"
	"github.com/spf13/cobra"
)

var deleteExceptionsExamples = `
  # Delete single exception
  kubescape delete exceptions "exception name"

  # Delete multiple exceptions
  kubescape delete exceptions "first exception;second exception;third exception"
`

func GetDeleteCmd() *cobra.Command {
	var deleteInfo cliobjects.Delete

	var deleteCmd = &cobra.Command{
		Use:   "delete <command>",
		Short: "Delete configurations in Kubescape SaaS version",
		Long:  ``,
		Run: func(cmd *cobra.Command, args []string) {
		},
	}
	deleteCmd.PersistentFlags().StringVarP(&deleteInfo.Account, "account", "", "", "Armo portal account ID. Default will load account ID from configMap or config file")

	deleteCmd.AddCommand(getExceptionsCmd(&deleteInfo))

	return deleteCmd
}
