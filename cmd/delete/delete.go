package delete

import (
	"github.com/armosec/kubescape/core/meta"
	v1 "github.com/armosec/kubescape/core/meta/datastructures/v1"
	"github.com/spf13/cobra"
)

var deleteExceptionsExamples = `
  # Delete single exception
  kubescape delete exceptions "exception name"

  # Delete multiple exceptions
  kubescape delete exceptions "first exception;second exception;third exception"
`

func GetDeleteCmd(ks meta.IKubescape) *cobra.Command {
	var deleteInfo v1.Delete

	var deleteCmd = &cobra.Command{
		Use:   "delete <command>",
		Short: "Delete configurations in Kubescape SaaS version",
		Long:  ``,
		Run: func(cmd *cobra.Command, args []string) {
		},
	}
	deleteCmd.PersistentFlags().StringVarP(&deleteInfo.Account, "account", "", "", "Armo portal account ID. Default will load account ID from configMap or config file")

	deleteCmd.AddCommand(getExceptionsCmd(ks, &deleteInfo))

	return deleteCmd
}
