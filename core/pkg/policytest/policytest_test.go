package policytest

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
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

// TestCompare_SameMessageAndPathCountSortsByContent proves that two
// responses sharing an AlertMessage and the same number of FailedPaths, but
// different path contents, still sort deterministically: reversing their
// order in got must not produce a false diff against want.
func TestCompare_SameMessageAndPathCountSortsByContent(t *testing.T) {
	x := reporthandling.RuleResponse{
		AlertMessage: "same alert",
		AssistedRemediation: reporthandling.AssistedRemediation{
			FailedPaths: []string{"spec.a"},
		},
	}
	y := reporthandling.RuleResponse{
		AlertMessage: "same alert",
		AssistedRemediation: reporthandling.AssistedRemediation{
			FailedPaths: []string{"spec.b"},
		},
	}

	want := []reporthandling.RuleResponse{x, y}
	got := []reporthandling.RuleResponse{y, x}

	assert.Empty(t, Compare(got, want), "reversed order of same-message, same-count responses must still compare equal")
}

// TestCompare_TiedOnPathsDistinguishedByFixPaths covers the exact tie the
// earlier fix missed: two responses with identical AlertMessage, FailedPaths,
// ReviewPaths, and DeletePaths, differing only in FixPaths. A sort key that
// ignores FixPaths treats them as equal and leaves their relative order to
// sort.Slice's unspecified tie-breaking, which can then disagree between got
// and want even though both sets are logically equal.
func TestCompare_TiedOnPathsDistinguishedByFixPaths(t *testing.T) {
	base := reporthandling.RuleResponse{
		AlertMessage: "same alert",
		AssistedRemediation: reporthandling.AssistedRemediation{
			FailedPaths: []string{"spec.a"},
		},
	}
	x := base
	x.FixPaths = []armotypes.FixPath{{Path: "spec.a", Value: "true"}}
	y := base
	y.FixPaths = []armotypes.FixPath{{Path: "spec.a", Value: "false"}}

	want := []reporthandling.RuleResponse{x, y}
	got := []reporthandling.RuleResponse{y, x}

	assert.Empty(t, Compare(got, want), "reversed order of responses tied on paths but distinct FixPaths must still compare equal")
}

// TestCompareFixPathsWithSamePath verifies that values break path-order ties without hiding real differences or duplicate counts.
func TestCompareFixPathsWithSamePath(t *testing.T) {
	first := armotypes.FixPath{Path: "spec.mode", Value: "first"}
	second := armotypes.FixPath{Path: "spec.mode", Value: "second"}
	tests := []struct {
		name  string
		got   []armotypes.FixPath
		want  []armotypes.FixPath
		equal bool
	}{
		{name: "reversed values", got: []armotypes.FixPath{second, first}, want: []armotypes.FixPath{first, second}, equal: true},
		{name: "reordered duplicates", got: []armotypes.FixPath{second, first, first}, want: []armotypes.FixPath{first, second, first}, equal: true},
		{name: "changed value", got: []armotypes.FixPath{first}, want: []armotypes.FixPath{second}},
		{name: "missing duplicate", got: []armotypes.FixPath{first, second}, want: []armotypes.FixPath{first, first, second}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := []reporthandling.RuleResponse{{AssistedRemediation: reporthandling.AssistedRemediation{FixPaths: tt.got}}}
			want := []reporthandling.RuleResponse{{AssistedRemediation: reporthandling.AssistedRemediation{FixPaths: tt.want}}}
			assert.Equal(t, tt.equal, Compare(got, want) == "")
		})
	}
}

// TestRunRuleIgnoresFixPathValueOrder exercises real evaluation and fixture updates when equal-path fixes are reordered.
func TestRunRuleIgnoresFixPathValueOrder(t *testing.T) {
	rule := scaffoldedRuleUnderTest(t)
	c := caseByName(t, rule, flaggedCaseName)
	rule.Rule.Rule = strings.Replace(rule.Rule.Rule, `"fixPaths": [],`, `"fixPaths": [{"path": "spec.mode", "value": "first"}, {"path": "spec.mode", "value": "second"}],`, 1)

	responses, err := EvaluateCase(context.Background(), rule, c)
	require.NoError(t, err)
	require.Len(t, responses, 1)
	require.Len(t, responses[0].FixPaths, 2)
	responses[0].FixPaths[0], responses[0].FixPaths[1] = responses[0].FixPaths[1], responses[0].FixPaths[0]
	expected, err := json.MarshalIndent(responses, "", "  ")
	require.NoError(t, err)
	expectedPath := filepath.Join(c.Dir, expectedFileName)
	require.NoError(t, os.WriteFile(expectedPath, expected, 0o600))

	for _, result := range RunRule(context.Background(), rule) {
		require.NoError(t, result.Err)
		assert.True(t, result.Passed, "case %s: %s", result.CaseName, result.Diff)
	}
	responses, err = EvaluateCase(context.Background(), rule, c)
	require.NoError(t, err)
	changed, err := WriteExpected(c, responses)
	require.NoError(t, err)
	assert.False(t, changed, "reordering equal-path fixes must not rewrite expected.json")
	actual, err := os.ReadFile(expectedPath)
	require.NoError(t, err)
	assert.Equal(t, string(expected), string(actual))
}
