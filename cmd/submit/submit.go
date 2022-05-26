package submit

import (
	"github.com/armosec/kubescape/v2/core/meta"
	metav1 "github.com/armosec/kubescape/v2/core/meta/datastructures/v1"
	"github.com/spf13/cobra"
)

var submitCmdExamples = `

`

func GetSubmitCmd(ks meta.IKubescape) *cobra.Command {
	var submitInfo metav1.Submit

	submitCmd := &cobra.Command{
		Use:   "submit <command>",
		Short: "Submit an object to the Kubescape SaaS version",
		Long:  ``,
		Run: func(cmd *cobra.Command, args []string) {
		},
	}
	submitCmd.PersistentFlags().StringVarP(&submitInfo.Credentials.Account, "account", "", "", "Kubescape SaaS account ID. Default will load account ID from cache")
	submitCmd.PersistentFlags().StringVarP(&submitInfo.Credentials.ClientID, "client-id", "", "", "Kubescape SaaS client ID. Default will load client ID from cache, read more - https://hub.armo.cloud/docs/authentication")
	submitCmd.PersistentFlags().StringVarP(&submitInfo.Credentials.SecretKey, "secret-key", "", "", "Kubescape SaaS secret key. Default will load secret key from cache, read more - https://hub.armo.cloud/docs/authentication")

	submitCmd.AddCommand(getExceptionsCmd(ks, &submitInfo))
	submitCmd.AddCommand(getResultsCmd(ks, &submitInfo))
	submitCmd.AddCommand(getRBACCmd(ks, &submitInfo))

	return submitCmd
}
