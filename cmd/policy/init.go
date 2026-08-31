package policy

import (
	"context"
	"fmt"
	"strings"

	"github.com/kubescape/kubescape/v4/core/pkg/policytest"
	"github.com/spf13/cobra"
)

func getPolicyInitCmd() *cobra.Command {
	var opts policytest.ScaffoldOptions

	cmd := &cobra.Command{
		Use:   "init <path>",
		Short: "Scaffold a custom Rego control with runnable test fixtures",
		Long: fmt.Sprintf(`Creates a rule directory at <path> holding raw.rego, rule.metadata.json and two test cases (%s and %s), then records each case's evaluator output in its expected.json so 'policy test' passes straight away.

The directory name becomes the rule name, and 'scan --custom-rules' picks it up from the parent directory.`,
			"flagged", "clean"),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyInit(cmd, args[0], opts)
		},
	}

	cmd.Flags().StringVar(&opts.Kind, "kind", "Deployment", fmt.Sprintf("Kubernetes kind the generated rule matches. Supported: %s", strings.Join(policytest.SupportedKinds(), ", ")))
	cmd.Flags().StringVar(&opts.Description, "description", "", "Rule description recorded in rule.metadata.json")
	cmd.Flags().StringVar(&opts.Remediation, "remediation", "", "Remediation text recorded in rule.metadata.json")
	cmd.Flags().BoolVar(&opts.Force, "force", false, "Overwrite an existing rule directory")

	return cmd
}

func runPolicyInit(cmd *cobra.Command, path string, opts policytest.ScaffoldOptions) error {
	files, err := policytest.Scaffold(context.Background(), path, opts)

	out := cmd.OutOrStdout()
	for _, file := range files {
		fmt.Fprintf(out, "wrote %s\n", file)
	}
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "\nRun '%s policy test %s' to verify.\n", cmd.Root().Name(), path)

	return nil
}
