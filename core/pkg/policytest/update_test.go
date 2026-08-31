package policytest

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func scaffoldedRuleUnderTest(t *testing.T) RuleUnderTest {
	t.Helper()
	dir := scaffoldRule(t, "update-target", ScaffoldOptions{})
	rules, err := DiscoverPath(dir)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	return rules[0]
}

func caseByName(t *testing.T, rule RuleUnderTest, name string) Case {
	t.Helper()
	for _, c := range rule.Cases {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("case %q not found", name)
	return Case{}
}

func TestEvaluateCase_DoesNotRequireExpectedFile(t *testing.T) {
	rule := scaffoldedRuleUnderTest(t)
	c := caseByName(t, rule, flaggedCaseName)
	require.NoError(t, os.Remove(filepath.Join(c.Dir, expectedFileName)))

	responses, err := EvaluateCase(context.Background(), rule, c)
	require.NoError(t, err)
	assert.Len(t, responses, 1)
}

func TestWriteExpected_ReportsChangeOnlyWhenContentDiffers(t *testing.T) {
	rule := scaffoldedRuleUnderTest(t)
	c := caseByName(t, rule, flaggedCaseName)

	responses, err := EvaluateCase(context.Background(), rule, c)
	require.NoError(t, err)

	changed, err := WriteExpected(c, responses)
	require.NoError(t, err)
	assert.False(t, changed, "Scaffold already recorded the evaluator's output")

	require.NoError(t, os.WriteFile(filepath.Join(c.Dir, expectedFileName), []byte("[]\n"), 0o600))
	changed, err = WriteExpected(c, responses)
	require.NoError(t, err)
	assert.True(t, changed)
}

func TestWriteExpected_CreatesMissingFileWithEmptyList(t *testing.T) {
	rule := scaffoldedRuleUnderTest(t)
	c := caseByName(t, rule, cleanCaseName)
	path := filepath.Join(c.Dir, expectedFileName)
	require.NoError(t, os.Remove(path))

	changed, err := WriteExpected(c, nil)
	require.NoError(t, err)
	assert.True(t, changed)

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "[]\n", string(raw))
}

func TestUpdateRule_RepairsBrokenExpectations(t *testing.T) {
	rule := scaffoldedRuleUnderTest(t)
	c := caseByName(t, rule, flaggedCaseName)
	require.NoError(t, os.WriteFile(filepath.Join(c.Dir, expectedFileName), []byte("[]\n"), 0o600))

	for _, result := range RunRule(context.Background(), rule) {
		if result.CaseName == flaggedCaseName {
			require.False(t, result.Passed, "precondition: the case must be failing")
		}
	}

	changedCases := map[string]bool{}
	for _, result := range UpdateRule(context.Background(), rule) {
		require.NoError(t, result.Err)
		changedCases[result.CaseName] = result.Changed
	}
	assert.True(t, changedCases[flaggedCaseName])
	assert.False(t, changedCases[cleanCaseName])

	for _, result := range RunRule(context.Background(), rule) {
		require.NoError(t, result.Err)
		assert.True(t, result.Passed, result.Diff)
	}
}

func TestUpdateRule_ReportsEvaluationFailure(t *testing.T) {
	rule := scaffoldedRuleUnderTest(t)
	rule.Rule.Rule = "package armo_builtins\nthis is not valid rego {{{"

	results := UpdateRule(context.Background(), rule)
	require.NotEmpty(t, results)
	for _, result := range results {
		assert.Error(t, result.Err)
		assert.False(t, result.Changed)
	}
}

func TestWriteExpected_OutputRoundTripsThroughLoad(t *testing.T) {
	rule := scaffoldedRuleUnderTest(t)
	c := caseByName(t, rule, flaggedCaseName)

	responses, err := EvaluateCase(context.Background(), rule, c)
	require.NoError(t, err)
	_, err = WriteExpected(c, responses)
	require.NoError(t, err)

	loaded, err := LoadCaseExpected(c.Dir)
	require.NoError(t, err)
	assert.Empty(t, Compare(responses, loaded))
	assert.IsType(t, []reporthandling.RuleResponse{}, loaded)
}

func TestWriteExpected_LeavesCosmeticallyDifferentFixtureAlone(t *testing.T) {
	rule := scaffoldedRuleUnderTest(t)
	c := caseByName(t, rule, flaggedCaseName)

	responses, err := EvaluateCase(context.Background(), rule, c)
	require.NoError(t, err)

	compact, err := json.Marshal(responses)
	require.NoError(t, err)
	path := filepath.Join(c.Dir, expectedFileName)
	require.NoError(t, os.WriteFile(path, compact, 0o600))

	changed, err := WriteExpected(c, responses)
	require.NoError(t, err)
	assert.False(t, changed, "a semantically equal fixture must not be rewritten")

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(compact), string(raw), "the file must be left byte-for-byte alone")
}

func TestUpdateRule_IsNoOpForInTreeRules(t *testing.T) {
	rules, err := Discover(rulesRoot(t))
	require.NoError(t, err)
	require.NotEmpty(t, rules)

	for _, rule := range rules {
		for _, result := range UpdateRule(context.Background(), rule) {
			require.NoError(t, result.Err)
			assert.False(t, result.Changed, "%s/%s: committed fixture must not be rewritten", result.RuleName, result.CaseName)
		}
	}
}
