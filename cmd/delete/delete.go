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
	deleteCmd.PersistentFlags().StringVarP(&deleteInfo.Credentials.ClientID, "client-id", "", "", "Kubescape SaaS client ID. Default will load client ID from cache, read more - https://hub.armosec.io/docs/authentication")
	deleteCmd.PersistentFlags().StringVarP(&deleteInfo.Credentials.SecretKey, "secret-key", "", "", "Kubescape SaaS secret key. Default will load secret key from cache, read more - https://hub.armosec.io/docs/authentication")

	deleteCmd.AddCommand(getExceptionsCmd(ks, &deleteInfo))

	return deleteCmd
}
