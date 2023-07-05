package submit

import (
	"fmt"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/meta"
	metav1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"
	"github.com/spf13/cobra"
)

var submitCmdExamples = fmt.Sprintf(`
# Submit Kubescape scan results file
%[1]s submit results

# Submit exceptions file to Kubescape SaaS
%[1]s submit exceptions
`, cautils.ExecName())

func GetSubmitCmd(ks meta.IKubescape) *cobra.Command {
	var submitInfo metav1.Submit

	submitCmd := &cobra.Command{
		Use:     "submit <command>",
		Short:   "Submit an object to the Kubescape SaaS version",
		Long:    ``,
		Example: submitCmdExamples,
		Run: func(cmd *cobra.Command, args []string) {
		},
	}
	submitCmd.PersistentFlags().StringVarP(&submitInfo.Credentials.Account, "account", "", "", "Kubescape SaaS account ID. Default will load account ID from cache")

	submitCmd.AddCommand(getExceptionsCmd(ks, &submitInfo))
	submitCmd.AddCommand(getResultsCmd(ks, &submitInfo))
	submitCmd.AddCommand(getRBACCmd(ks, &submitInfo))

	return submitCmd
}
