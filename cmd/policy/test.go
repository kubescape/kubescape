package policy

import (
	"context"
	"fmt"

	"github.com/kubescape/kubescape/v4/core/pkg/policytest"
	"github.com/spf13/cobra"
)

func getPolicyTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test <path>",
		Short: "Run a Rego control's test fixtures and report pass/fail",
		Long:  `Discovers rule directories (raw.rego + rule.metadata.json, with test cases under test/<case>/{input,expected.json}) under <path>, evaluates every case, and reports which ones match their expected.json.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyTest(cmd, args[0])
		},
	}
}

func runPolicyTest(cmd *cobra.Command, path string) error {
	rules, err := policytest.DiscoverPath(path)
	if err != nil {
		return fmt.Errorf("discover rules: %w", err)
	}
	if len(rules) == 0 {
		return fmt.Errorf("no rule directories (raw.rego + rule.metadata.json) found under %q", path)
	}

	ctx := context.Background()
	total, failed := 0, 0
	for _, rule := range rules {
		if len(rule.Cases) == 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "%s: no test cases\n", rule.Name)
			continue
		}
		for _, result := range policytest.RunRule(ctx, rule) {
			total++
			switch {
			case result.Err != nil:
				failed++
				fmt.Fprintf(cmd.OutOrStdout(), "FAIL %s/%s: %v\n", result.RuleName, result.CaseName, result.Err)
			case !result.Passed:
				failed++
				fmt.Fprintf(cmd.OutOrStdout(), "FAIL %s/%s\n%s\n", result.RuleName, result.CaseName, result.Diff)
			default:
				fmt.Fprintf(cmd.OutOrStdout(), "PASS %s/%s\n", result.RuleName, result.CaseName)
			}
		}
	}

	fmt.Fprintf(cmd.OutOrStdout(), "\n%d/%d cases passed\n", total-failed, total)
	if failed > 0 {
		return fmt.Errorf("%d test case(s) failed", failed)
	}
	return nil
}
