package submit

import (
	"github.com/armosec/kubescape/clihandler/cliobjects"
	"github.com/spf13/cobra"
)

var submitCmdExamples = `

`

func GetSubmitCmd() *cobra.Command {
	var submitInfo cliobjects.Submit

	submitCmd := &cobra.Command{
		Use:   "submit <command>",
		Short: "Submit an object to the Kubescape SaaS version",
		Long:  ``,
		Run: func(cmd *cobra.Command, args []string) {
		},
	}
	submitCmd.PersistentFlags().StringVarP(&submitInfo.Account, "account", "", "", "Armo portal account ID. Default will load account ID from configMap or config file")

	submitCmd.AddCommand(getExceptionsCmd(&submitInfo))
	submitCmd.AddCommand(getResultsCmd(&submitInfo))
	submitCmd.AddCommand(getRBACCmd(&submitInfo))

	return submitCmd
}
