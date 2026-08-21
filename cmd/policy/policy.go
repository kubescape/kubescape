package policy

import (
	"fmt"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/spf13/cobra"
)

var policyCmdExamples = fmt.Sprintf(`
  policy command can be used for authoring and testing custom Rego controls.
  This is an experimental feature and it might change.

  Examples:

  # Run every rule's test fixtures under a directory
  %[1]s policy test ./rules

  # Run a single rule's test fixtures
  %[1]s policy test ./rules/my-custom-rule
`, cautils.ExecName())

func GetPolicyCmd() *cobra.Command {
	policyCmd := &cobra.Command{
		Use:     "policy",
		Short:   "Author and test custom Rego controls",
		Long:    ``,
		Example: policyCmdExamples,
	}

	policyCmd.AddCommand(getPolicyTestCmd())

	return policyCmd
}
