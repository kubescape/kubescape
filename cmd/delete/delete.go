package delete

import (
	"fmt"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/meta"
	v1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"
	"github.com/spf13/cobra"
)

var deleteExceptionsExamples = fmt.Sprintf(`
  # Delete single exception
  %[1]s delete exceptions "exception name"

  # Delete multiple exceptions
  %[1]s delete exceptions "first exception;second exception;third exception"
`, cautils.ExecName())

func GetDeleteCmd(ks meta.IKubescape) *cobra.Command {
	var deleteInfo v1.Delete

	var deleteCmd = &cobra.Command{
		Use:   "delete <command>",
		Short: "Delete configurations in Kubescape SaaS version",
		Long:  ``,
		Run: func(cmd *cobra.Command, args []string) {
		},
	}
	deleteCmd.PersistentFlags().StringVarP(&deleteInfo.Credentials.Account, "account", "", "", "Kubescape SaaS account ID. Default will load account ID from cache")

	deleteCmd.AddCommand(getExceptionsCmd(ks, &deleteInfo))

	return deleteCmd
}
