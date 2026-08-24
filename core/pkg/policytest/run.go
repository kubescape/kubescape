package policytest

import (
	"context"
	"fmt"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/opaprocessor"
	"github.com/kubescape/opa-utils/resources"
)

// CaseResult is the outcome of running one test case.
type CaseResult struct {
	RuleName string
	CaseName string
	Passed   bool
	// Err is set when the case could not be loaded or evaluated at all,
	// distinct from a Diff (loaded and evaluated, but the output differs).
	Err  error
	Diff string
}

// RunRule loads and runs every case under rule, returning one CaseResult per
// case. A rule with no cases returns an empty, non-nil slice.
func RunRule(ctx context.Context, rule RuleUnderTest) []CaseResult {
	results := make([]CaseResult, 0, len(rule.Cases))
	for _, c := range rule.Cases {
		results = append(results, runCase(ctx, rule, c))
	}
	return results
}

func runCase(ctx context.Context, rule RuleUnderTest, c Case) CaseResult {
	result := CaseResult{RuleName: rule.Name, CaseName: c.Name}

	resourcesToScan, err := LoadCaseInput(c.Dir)
	if err != nil {
		result.Err = fmt.Errorf("load input: %w", err)
		return result
	}
	expected, err := LoadCaseExpected(c.Dir)
	if err != nil {
		result.Err = fmt.Errorf("load expected: %w", err)
		return result
	}

	sessionObj := cautils.NewOPASessionObjMock()
	proc := opaprocessor.NewOPAProcessor(sessionObj, &resources.RegoDependenciesData{}, "", "", "", false, nil)

	got, err := proc.EvaluateRule(ctx, &rule.Rule, resourcesToScan, rule.Name)
	if err != nil {
		result.Err = fmt.Errorf("evaluate rule: %w", err)
		return result
	}

	diff := Compare(got, expected)
	result.Passed = diff == ""
	result.Diff = diff
	return result
}
