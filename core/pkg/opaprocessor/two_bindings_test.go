package opaprocessor

import (
	"context"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1unstructured "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// twoBindingsTestPods returns a privileged Pod and a clean one.
func twoBindingsTestPods() []map[string]any {
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

func scanC0057WithBindings(t *testing.T, bindings []metav1unstructured.Unstructured) (map[string]apis.ScanningStatus, error) {
	t.Helper()
	rule := reporthandling.PolicyRule{
		PortalBase:   armotypes.PortalBase{Name: "rule-privilege-escalation"},
		RuleLanguage: reporthandling.CELLanguage,
		Match:        podMatch,
	}
	control := reporthandling.Control{ControlID: "C-0057", Rules: []reporthandling.PolicyRule{rule}}
	scanner := newParityScanner(t, twoBindingsTestPods(), nil)
	scanner.VAPBindings = bindings

	results, err := scanner.processRule(context.Background(), &rule, nil, evaluationScope{}, &control)
	statuses := map[string]apis.ScanningStatus{}
	for id, result := range results {
		statuses[id] = result.Status
	}
	return statuses, err
}

// A policy with no params reads nothing from its bindings, so two bindings
// (a Deny one and a Warn one, say) give the verdicts one binding gives. Before,
// the control was skipped as not evaluated.
func TestTwoBindingsOnAPolicyWithoutParamsStillScan(t *testing.T) {
	one, err := scanC0057WithBindings(t, []metav1unstructured.Unstructured{liveBinding(t, "C-0057", "deny")})
	require.NoError(t, err)
	two, err := scanC0057WithBindings(t, []metav1unstructured.Unstructured{
		liveBinding(t, "C-0057", "deny"),
		liveBinding(t, "C-0057", "warn"),
	})
	require.NoError(t, err)

	assert.Equal(t, apis.StatusFailed, two["/v1/default/Pod/leaky"])
	assert.Equal(t, apis.StatusPassed, two["/v1/default/Pod/clean"])
	assert.Equal(t, one, two)
}

// A policy that takes params, with bindings that supply none, is evaluated
// against the bundled defaults whether it has one binding or several.
func TestTwoBindingsWithoutParamRefsUseTheBundledDefaults(t *testing.T) {
	rule := reporthandling.PolicyRule{
		PortalBase:   armotypes.PortalBase{Name: "rule-resources-limits"},
		RuleLanguage: reporthandling.CELLanguage,
		Match:        podMatch,
	}
	control := reporthandling.Control{ControlID: "C-0004", Rules: []reporthandling.PolicyRule{rule}}
	run := func(bindings ...metav1unstructured.Unstructured) map[string]apis.ScanningStatus {
		scanner := newParityScanner(t, twoBindingsTestPods(), nil)
		scanner.VAPBindings = bindings
		results, err := scanner.processRule(context.Background(), &rule, nil, evaluationScope{}, &control)
		require.NoError(t, err)
		statuses := map[string]apis.ScanningStatus{}
		for id, result := range results {
			statuses[id] = result.Status
		}
		return statuses
	}

	assert.Equal(t,
		run(liveBinding(t, "C-0004", "binding-a")),
		run(liveBinding(t, "C-0004", "binding-a"), liveBinding(t, "C-0004", "binding-b")))
}

// Two bindings that name params still cannot be told apart per object, so the
// scan keeps refusing them rather than guess which params apply.
func TestTwoBindingsWithParamRefsAreStillRefused(t *testing.T) {
	rule := reporthandling.PolicyRule{
		PortalBase:   armotypes.PortalBase{Name: "rule-resources-limits"},
		RuleLanguage: reporthandling.CELLanguage,
		Match:        podMatch,
	}
	control := reporthandling.Control{ControlID: "C-0004", Rules: []reporthandling.PolicyRule{rule}}
	scanner := newParityScanner(t, twoBindingsTestPods(), nil)
	scanner.VAPBindings = []metav1unstructured.Unstructured{
		liveBindingWithParamRef(t, "C-0004", "binding-a", "params-a"),
		liveBinding(t, "C-0004", "binding-b"),
	}

	_, err := scanner.processRule(context.Background(), &rule, nil, evaluationScope{}, &control)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is matched by 2 live bindings")
}
