package submit

import (
	"github.com/armosec/kubescape/core/meta"
	metav1 "github.com/armosec/kubescape/core/meta/datastructures/v1"
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
	submitCmd.PersistentFlags().StringVarP(&submitInfo.Account, "account", "", "", "Armo portal account ID. Default will load account ID from configMap or config file")

	submitCmd.AddCommand(getExceptionsCmd(ks, &submitInfo))
	submitCmd.AddCommand(getResultsCmd(ks, &submitInfo))
	submitCmd.AddCommand(getRBACCmd(ks, &submitInfo))

	return submitCmd
}
