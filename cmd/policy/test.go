package policy

import (
	"fmt"

	"github.com/jwalton/gchalk"
	"github.com/kubescape/kubescape/v4/core/pkg/policytest"
	"github.com/spf13/cobra"
)

func getPolicyTestCmd() *cobra.Command {
	var update bool

	cmd := &cobra.Command{
		Use:   "test <path>",
		Short: "Run a Rego control's test fixtures and report pass/fail",
		Long:  `Discovers rule directories (raw.rego + rule.metadata.json, with test cases under test/<case>/{input,expected.json}) under <path>, evaluates every case, and reports which ones match their expected.json.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if update {
				return runPolicyUpdate(cmd, args[0])
			}
			return runPolicyTest(cmd, args[0])
		},
	}

	cmd.Flags().BoolVar(&update, "update", false, "Rewrite each case's expected.json from the rule's current output instead of comparing against it")

	return cmd
}

func runPolicyUpdate(cmd *cobra.Command, path string) error {
	rules, err := discoverRules(path)
	if err != nil {
		return err
	}

	ctx := cmd.Context()
	changed, failed := 0, 0
	out := cmd.OutOrStdout()
	colored := shouldColor(out)

	for _, rule := range rules {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(rule.Cases) == 0 {
			msg := fmt.Sprintf("%s: no test cases\n", rule.Name)
			if colored {
				msg = fmt.Sprintf("%s: %s\n", gchalk.WithBrightCyan().Bold(rule.Name), gchalk.BrightYellow("no test cases"))
			}
			fmt.Fprint(out, msg)
			continue
		}
		for _, result := range policytest.UpdateRule(ctx, rule) {
			if err := ctx.Err(); err != nil {
				return err
			}
			ruleCase := fmt.Sprintf("%s/%s", result.RuleName, result.CaseName)
			switch {
			case result.Err != nil:
				failed++
				badge := "ERROR"
				if colored {
					badge = gchalk.WithBrightRed().Bold("ERROR")
					ruleCase = gchalk.WithBrightCyan().Bold(ruleCase)
				}
				fmt.Fprintf(out, "%s %s: %v\n", badge, ruleCase, result.Err)
			case result.Changed:
				changed++
				badge := "UPDATED"
				if colored {
					badge = gchalk.WithBrightYellow().Bold("UPDATED")
					ruleCase = gchalk.WithBrightCyan().Bold(ruleCase)
				}
				fmt.Fprintf(out, "%s %s\n", badge, ruleCase)
			default:
				badge := "UNCHANGED"
				if colored {
					badge = gchalk.Bold("UNCHANGED")
					ruleCase = gchalk.WithBrightCyan().Bold(ruleCase)
				}
				fmt.Fprintf(out, "%s %s\n", badge, ruleCase)
			}
		}
	}

	if colored {
		changedStr := gchalk.Bold(fmt.Sprintf("%d", changed))
		if changed > 0 {
			changedStr = gchalk.WithBrightYellow().Bold(fmt.Sprintf("%d", changed))
		}
		fmt.Fprintf(out, "\n%s case(s) updated\n", changedStr)
	} else {
		fmt.Fprintf(out, "\n%d case(s) updated\n", changed)
	}
	if failed > 0 {
		return fmt.Errorf("%d test case(s) could not be evaluated", failed)
	}
	return nil
}

func discoverRules(path string) ([]policytest.RuleUnderTest, error) {
	rules, err := policytest.DiscoverPath(path)
	if err != nil {
		return nil, fmt.Errorf("discover rules: %w", err)
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("no rule directories (raw.rego + rule.metadata.json) found under %q", path)
	}
	return rules, nil
}

func runPolicyTest(cmd *cobra.Command, path string) error {
	rules, err := discoverRules(path)
	if err != nil {
		return err
	}

	ctx := cmd.Context()
	total, failed := 0, 0
	out := cmd.OutOrStdout()
	colored := shouldColor(out)

	for _, rule := range rules {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(rule.Cases) == 0 {
			msg := fmt.Sprintf("%s: no test cases\n", rule.Name)
			if colored {
				msg = fmt.Sprintf("%s: %s\n", gchalk.WithBrightCyan().Bold(rule.Name), gchalk.BrightYellow("no test cases"))
			}
			fmt.Fprint(out, msg)
			continue
		}
		for _, result := range policytest.RunRule(ctx, rule) {
			if err := ctx.Err(); err != nil {
				return err
			}
			total++
			ruleCase := fmt.Sprintf("%s/%s", result.RuleName, result.CaseName)
			switch {
			case result.Err != nil:
				failed++
				badge := "FAIL"
				if colored {
					badge = gchalk.WithBrightRed().Bold("FAIL")
					ruleCase = gchalk.WithBrightCyan().Bold(ruleCase)
				}
				fmt.Fprintf(out, "%s %s: %v\n", badge, ruleCase, result.Err)
			case !result.Passed:
				failed++
				badge := "FAIL"
				if colored {
					badge = gchalk.WithBrightRed().Bold("FAIL")
					ruleCase = gchalk.WithBrightCyan().Bold(ruleCase)
				}
				fmt.Fprintf(out, "%s %s\n%s\n", badge, ruleCase, result.Diff)
			default:
				badge := "PASS"
				if colored {
					badge = gchalk.WithBrightGreen().Bold("PASS")
					ruleCase = gchalk.WithBrightCyan().Bold(ruleCase)
				}
				fmt.Fprintf(out, "%s %s\n", badge, ruleCase)
			}
		}
	}

	passedCount := total - failed
	if colored {
		passedStr := gchalk.WithBrightGreen().Bold(fmt.Sprintf("%d", passedCount))
		if passedCount == 0 && total > 0 {
			passedStr = gchalk.WithBrightRed().Bold(fmt.Sprintf("%d", passedCount))
		}
		totalStr := gchalk.Bold(fmt.Sprintf("%d", total))
		fmt.Fprintf(out, "\n%s/%s cases passed\n", passedStr, totalStr)
	} else {
		fmt.Fprintf(out, "\n%d/%d cases passed\n", passedCount, total)
	}
	if failed > 0 {
		return fmt.Errorf("%d test case(s) failed", failed)
	}
	return nil
}
