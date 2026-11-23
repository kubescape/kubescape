package opaprocessor

import (
	"context"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuleTextIsRego(t *testing.T) {
	cases := []struct {
		name string
		text string
		want bool
	}{
		{name: "package clause", text: "package armo_builtins\n\ndeny[msga] { true }", want: true},
		{name: "comments and blank lines first", text: "\n# generated\n\n  package armo_builtins\n", want: true},
		{name: "package clause with a tab", text: "package\tarmo_builtins\n", want: true},
		{name: "policy document", text: "apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingAdmissionPolicy\n", want: false},
		{name: "policy document after a comment preamble", text: "# @baseScore 9\n---\napiVersion: admissionregistration.k8s.io/v1\n", want: false},
		{name: "a key named package is not a package clause", text: "package: armo_builtins\n", want: false},
		{name: "package only as a later line", text: "kind: ValidatingAdmissionPolicy\nmessage: |\n  package armo_builtins\n", want: false},
		{name: "empty", text: "", want: false},
		{name: "comments only", text: "# nothing here\n", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ruleTextIsRego(tc.text))
		})
	}
}

func privilegedAndCleanPods() []map[string]any {
	pod := func(name string, privileged bool) map[string]any {
		container := map[string]any{"name": "app", "image": "nginx:1.25"}
		if privileged {
			container["securityContext"] = map[string]any{"privileged": true}
		}
		return map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata":   map[string]any{"name": name, "namespace": "default"},
			"spec":       map[string]any{"containers": []any{container}},
		}
	}
	return []map[string]any{pod("leaky", true), pod("clean", false)}
}

// A control document marked ruleLanguage CEL, the way docs/cel-engine.md says
// to try the engine, still holds the Rego it shipped with in `rule`. That text
// is not a policy, so the rule has to run the bundled policy for its control.
// Before, the Rego was parsed as an inline ValidatingAdmissionPolicy and the
// whole control was skipped as not evaluated.
func TestCELRuleHoldingRegoRunsTheBundledPolicy(t *testing.T) {
	rule := reporthandling.PolicyRule{
		PortalBase:   armotypes.PortalBase{Name: "rule-privilege-escalation"},
		RuleLanguage: reporthandling.CELLanguage,
		Rule:         "package armo_builtins\n\n# the Rego this control shipped with\ndeny[msga] {\n\tpod := input[_]\n\tpod.kind == \"Pod\"\n\tmsga := {}\n}\n",
		Match:        podMatch,
	}
	control := reporthandling.Control{ControlID: "C-0057", Rules: []reporthandling.PolicyRule{rule}}

	scanner := newParityScanner(t, privilegedAndCleanPods(), nil)
	results, err := scanner.processRule(context.Background(), &rule, nil, evaluationScope{}, &control)
	require.NoError(t, err)
	require.Len(t, results, 2)

	require.Contains(t, results, "/v1/default/Pod/leaky")
	assert.Equal(t, apis.StatusFailed, results["/v1/default/Pod/leaky"].Status)
	require.Contains(t, results, "/v1/default/Pod/clean")
	assert.Equal(t, apis.StatusPassed, results["/v1/default/Pod/clean"].Status)
}

// The same rule with no rule text takes the bundled policy too, so the two
// spellings of "run the bundled policy" agree.
func TestCELRuleWithoutTextAndWithRegoTextAgree(t *testing.T) {
	run := func(text string) map[string]apis.ScanningStatus {
		rule := reporthandling.PolicyRule{
			PortalBase:   armotypes.PortalBase{Name: "rule-privilege-escalation"},
			RuleLanguage: reporthandling.CELLanguage,
			Rule:         text,
			Match:        podMatch,
		}
		control := reporthandling.Control{ControlID: "C-0057", Rules: []reporthandling.PolicyRule{rule}}
		scanner := newParityScanner(t, privilegedAndCleanPods(), nil)
		results, err := scanner.processRule(context.Background(), &rule, nil, evaluationScope{}, &control)
		require.NoError(t, err)
		statuses := map[string]apis.ScanningStatus{}
		for id, result := range results {
			statuses[id] = result.Status
		}
		return statuses
	}
	assert.Equal(t, run(""), run("package armo_builtins\n\ndeny[msga] { false }\n"))
}

// An inline policy is still read as one. A malformed policy reports its own
// error: it must not fall back to a bundled policy that happens to share the
// control ID.
func TestCELRuleHoldingAMalformedPolicyStillErrors(t *testing.T) {
	rule := reporthandling.PolicyRule{
		PortalBase:   armotypes.PortalBase{Name: "rule-privilege-escalation"},
		RuleLanguage: reporthandling.CELLanguage,
		Rule:         "apiVersion: admissionregistration.k8s.io/v1\nkind: ConfigMap\n",
		Match:        podMatch,
	}
	control := reporthandling.Control{ControlID: "C-0057", Rules: []reporthandling.PolicyRule{rule}}

	scanner := newParityScanner(t, privilegedAndCleanPods(), nil)
	_, err := scanner.processRule(context.Background(), &rule, nil, evaluationScope{}, &control)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ValidatingAdmissionPolicy")
}
