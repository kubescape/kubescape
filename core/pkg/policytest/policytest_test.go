package policytest

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func rulesRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../../../rules")
	require.NoError(t, err)
	return root
}

func TestDiscover_FindsRuleDirectories(t *testing.T) {
	rules, err := Discover(rulesRoot(t))
	require.NoError(t, err)
	require.NotEmpty(t, rules)

	names := make(map[string]bool, len(rules))
	for _, r := range rules {
		names[r.Name] = true
		assert.NotEmpty(t, r.Rule.Rule, "rule %s: raw.rego must be loaded into PolicyRule.Rule", r.Name)
	}
	assert.True(t, names["modify-node-status-v1"])
}

func TestDiscoverPath_SingleRuleDirectory(t *testing.T) {
	dir := filepath.Join(rulesRoot(t), "modify-node-status-v1")
	rules, err := DiscoverPath(dir)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "modify-node-status-v1", rules[0].Name)
	assert.NotEmpty(t, rules[0].Cases)
}

func TestDiscoverPath_DirectoryOfRules(t *testing.T) {
	rules, err := DiscoverPath(rulesRoot(t))
	require.NoError(t, err)
	assert.Greater(t, len(rules), 1)
}

func TestRunRule_KnownGoodCasePasses(t *testing.T) {
	dir := filepath.Join(rulesRoot(t), "modify-node-status-v1")
	rules, err := DiscoverPath(dir)
	require.NoError(t, err)
	require.Len(t, rules, 1)

	results := RunRule(context.Background(), rules[0])
	require.NotEmpty(t, results)
	for _, r := range results {
		assert.NoError(t, r.Err, "case %s", r.CaseName)
		assert.True(t, r.Passed, "case %s: %s", r.CaseName, r.Diff)
	}
}

func TestCompare_IgnoresPathOrderAndResponseOrder(t *testing.T) {
	a := reporthandling.RuleResponse{
		AlertMessage: "alert A",
		AssistedRemediation: reporthandling.AssistedRemediation{
			FailedPaths: []string{"spec.foo", "spec.bar"},
		},
	}
	b := reporthandling.RuleResponse{
		AlertMessage: "alert B",
		AssistedRemediation: reporthandling.AssistedRemediation{
			FailedPaths: []string{"spec.baz"},
		},
	}
	aReordered := a
	aReordered.FailedPaths = []string{"spec.bar", "spec.foo"}

	got := []reporthandling.RuleResponse{b, aReordered}
	want := []reporthandling.RuleResponse{a, b}

	assert.Empty(t, Compare(got, want), "response order and path order must not affect equality")
}

func TestCompare_ReportsRealDifference(t *testing.T) {
	got := []reporthandling.RuleResponse{{AlertMessage: "alert A"}}
	want := []reporthandling.RuleResponse{{AlertMessage: "alert B"}}

	assert.NotEmpty(t, Compare(got, want))
}
