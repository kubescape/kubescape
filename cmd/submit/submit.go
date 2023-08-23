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
	submitCmd.PersistentFlags().StringVarP(&submitInfo.AccountID, "account", "", "", "Kubescape SaaS account ID. Default will load account ID from cache")
	submitCmd.PersistentFlags().MarkDeprecated("client-id", "Client ID is no longer supported. Feel free to contact the Kubescape maintainers for more information.")
	submitCmd.PersistentFlags().MarkDeprecated("secret-key", "Secret Key is no longer supported. Feel free to contact the Kubescape maintainers for more information.")

	submitCmd.AddCommand(getResultsCmd(ks, &submitInfo))

	// deprecated commands
	submitCmd.AddCommand(&cobra.Command{
		Use:        "exceptions",
		Deprecated: "Contact Kubescape maintainers for more information.",
	})
	submitCmd.AddCommand(&cobra.Command{
		Use:        "rbac",
		Deprecated: "Contact Kubescape maintainers for more information.",
	})
	return submitCmd
}
