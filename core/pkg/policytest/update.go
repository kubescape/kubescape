package policytest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/opaprocessor"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/resources"
)

const expectedFileName = "expected.json"

// UpdateResult is the outcome of regenerating one case's expected.json.
type UpdateResult struct {
	RuleName string
	CaseName string
	Changed  bool
	Err      error
}

// EvaluateCase runs rule against the case input and returns the responses the
// evaluator produced. It does not read expected.json, so it works for a case
// that does not have one yet.
func EvaluateCase(ctx context.Context, rule RuleUnderTest, c Case) ([]reporthandling.RuleResponse, error) {
	resourcesToScan, err := LoadCaseInput(c.Dir)
	if err != nil {
		return nil, fmt.Errorf("load input: %w", err)
	}

	sessionObj := cautils.NewOPASessionObjMock()
	proc := opaprocessor.NewOPAProcessor(sessionObj, &resources.RegoDependenciesData{}, "", "", "", false, nil)

	got, err := proc.EvaluateRule(ctx, &rule.Rule, resourcesToScan, rule.Name)
	if err != nil {
		return nil, fmt.Errorf("evaluate rule: %w", err)
	}
	return got, nil
}

// WriteExpected writes responses to the case's expected.json and reports
// whether it rewrote the file. A file the rule already satisfies is left
// untouched: equality here is the same comparison RunRule applies, so a fixture
// that differs only in field order, path order or an omitted empty list is not
// rewritten for cosmetic reasons.
func WriteExpected(c Case, responses []reporthandling.RuleResponse) (bool, error) {
	if responses == nil {
		responses = []reporthandling.RuleResponse{}
	}

	if existing, err := LoadCaseExpected(c.Dir); err == nil && Compare(responses, existing) == "" {
		return false, nil
	}

	encoded, err := json.MarshalIndent(responses, "", "    ")
	if err != nil {
		return false, fmt.Errorf("encode responses: %w", err)
	}
	encoded = append(encoded, '\n')

	path := filepath.Join(c.Dir, expectedFileName)
	if err := os.WriteFile(path, encoded, filePerm); err != nil {
		return false, fmt.Errorf("write %s: %w", expectedFileName, err)
	}
	return true, nil
}

// UpdateRule regenerates expected.json for every case under rule.
func UpdateRule(ctx context.Context, rule RuleUnderTest) []UpdateResult {
	results := make([]UpdateResult, 0, len(rule.Cases))
	for _, c := range rule.Cases {
		result := UpdateResult{RuleName: rule.Name, CaseName: c.Name}

		responses, err := EvaluateCase(ctx, rule, c)
		if err != nil {
			result.Err = err
			results = append(results, result)
			continue
		}

		changed, err := WriteExpected(c, responses)
		result.Changed = changed
		result.Err = err
		results = append(results, result)
	}
	return results
}
