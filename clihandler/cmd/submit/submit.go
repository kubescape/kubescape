package submit

import (
	"github.com/armosec/kubescape/clihandler/cliobjects"
	"github.com/spf13/cobra"
)

var submitInfo cliobjects.Submit

var submitCmdExamples = `

`

func GetSubmitCmd() *cobra.Command {
	submitCmd := &cobra.Command{
		Use:   "submit <command>",
		Short: "Submit an object to the Kubescape SaaS version",
		Long:  ``,
		Run: func(cmd *cobra.Command, args []string) {
		},
	}
	submitCmd.PersistentFlags().StringVarP(&submitInfo.Account, "account", "", "", "Armo portal account ID. Default will load account ID from configMap or config file")

	submitCmd.AddCommand(getExceptionsCmd())
	submitCmd.AddCommand(getResultsCmd())
	submitCmd.AddCommand(getRBACCmd())

	return submitCmd
}
