package policy

import (
	"fmt"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/spf13/cobra"
)

var policyCmdExamples = fmt.Sprintf(`
  Scaffold custom Rego controls and test Rego or CEL policies.
  This is an experimental feature and it might change.

  Examples:

  # Run every rule's test fixtures under a directory
  %[1]s policy test ./rules

  # Run a single rule's test fixtures
  %[1]s policy test ./rules/my-custom-rule

  # Scaffold a new rule, with fixtures that already pass
  %[1]s policy init ./rules/no-privileged-containers

  # Scaffold a rule matching a different kind
  %[1]s policy init ./rules/no-privileged-pods --kind Pod

  # Rewrite the fixtures' expected.json from the rule's current output
  %[1]s policy test ./rules/my-custom-rule --update

  # Also write the results as a JUnit XML report for a CI system
  %[1]s policy test ./rules --junit-report policy-test.xml
`, cautils.ExecName())

func GetPolicyCmd() *cobra.Command {
	policyCmd := &cobra.Command{
		Use:     "policy",
		Short:   "Scaffold Rego controls and test Rego or CEL policies",
		Long:    ``,
		Example: policyCmdExamples,
	}

	policyCmd.AddCommand(getPolicyInitCmd())
	policyCmd.AddCommand(getPolicyTestCmd())

	return policyCmd
}
