package vapreconcile

import (
	"testing"

	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func makeVAP(name, controlID string) unstructured.Unstructured {
	u := unstructured.Unstructured{}
	u.SetName(name)
	if controlID != "" {
		u.SetLabels(map[string]string{"controlId": controlID})
	}
	return u
}

func makeVAPB(name, policyName string, actions []string) unstructured.Unstructured {
	u := unstructured.Unstructured{
		Object: map[string]any{
			"spec": map[string]any{
				"policyName":        policyName,
				"validationActions": toInterfaceSlice(actions),
			},
		},
	}
	u.SetName(name)
	return u
}

func toInterfaceSlice(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func TestBuildIndex_BoundDeny(t *testing.T) {
	policies := []unstructured.Unstructured{
		makeVAP("kubescape-c-0041-deny-host-network", "C-0041"),
	}
	bindings := []unstructured.Unstructured{
		makeVAPB("c0041-binding", "kubescape-c-0041-deny-host-network", []string{"Deny"}),
	}

	index := BuildIndex(policies, bindings)

	assert.Contains(t, index, "C-0041")
	assert.Equal(t, "kubescape-c-0041-deny-host-network", index["C-0041"].PolicyName)
	assert.True(t, index["C-0041"].Bound)
	assert.Equal(t, []string{"Deny"}, index["C-0041"].Actions)
}

func TestBuildIndex_BoundWarn(t *testing.T) {
	policies := []unstructured.Unstructured{
		makeVAP("kubescape-c-0016-privilege-escalation", "C-0016"),
	}
	bindings := []unstructured.Unstructured{
		makeVAPB("c0016-binding", "kubescape-c-0016-privilege-escalation", []string{"Warn"}),
	}

	index := BuildIndex(policies, bindings)

	assert.True(t, index["C-0016"].Bound)
	assert.Equal(t, []string{"Warn"}, index["C-0016"].Actions)
}

func TestBuildIndex_VAPWithNoBinding(t *testing.T) {
	policies := []unstructured.Unstructured{
		makeVAP("kubescape-c-0038-host-ipc", "C-0038"),
	}

	index := BuildIndex(policies, nil)

	assert.Contains(t, index, "C-0038")
	assert.False(t, index["C-0038"].Bound)
	assert.Nil(t, index["C-0038"].Actions)
}

func TestBuildIndex_VAPWithNoControlIDLabel(t *testing.T) {
	// VAPs without controlId label (e.g. runtime policies) should be ignored
	policies := []unstructured.Unstructured{
		makeVAP("cluster-policy-deny-exec", ""),
	}

	index := BuildIndex(policies, nil)

	assert.Empty(t, index)
}

func TestBuildIndex_BindingForUnknownPolicy(t *testing.T) {
	// binding points to a policy not in our VAP list — should not panic or error
	policies := []unstructured.Unstructured{
		makeVAP("kubescape-c-0041-deny-host-network", "C-0041"),
	}
	bindings := []unstructured.Unstructured{
		makeVAPB("unknown-binding", "some-other-policy", []string{"Deny"}),
	}

	index := BuildIndex(policies, bindings)

	assert.False(t, index["C-0041"].Bound)
}

func TestBuildIndex_MultipleControls(t *testing.T) {
	policies := []unstructured.Unstructured{
		makeVAP("kubescape-c-0041-deny-host-network", "C-0041"),
		makeVAP("kubescape-c-0016-privilege-escalation", "C-0016"),
		makeVAP("kubescape-c-0038-host-ipc", "C-0038"),
	}
	bindings := []unstructured.Unstructured{
		makeVAPB("c0041-binding", "kubescape-c-0041-deny-host-network", []string{"Warn"}),
		makeVAPB("c0016-binding", "kubescape-c-0016-privilege-escalation", []string{"Deny"}),
		// C-0038 has no binding
	}

	index := BuildIndex(policies, bindings)

	assert.Len(t, index, 3)
	assert.True(t, index["C-0041"].Bound)
	assert.Equal(t, []string{"Warn"}, index["C-0041"].Actions)
	assert.True(t, index["C-0016"].Bound)
	assert.Equal(t, []string{"Deny"}, index["C-0016"].Actions)
	assert.False(t, index["C-0038"].Bound)
}

func TestBuildIndex_SameControlMultipleBindings(t *testing.T) {
	// two bindings pointing at the same policy — actions should be merged, not overwritten
	policies := []unstructured.Unstructured{
		makeVAP("kubescape-c-0041-deny-host-network", "C-0041"),
	}
	bindings := []unstructured.Unstructured{
		makeVAPB("c0041-binding-deny", "kubescape-c-0041-deny-host-network", []string{"Deny"}),
		makeVAPB("c0041-binding-audit", "kubescape-c-0041-deny-host-network", []string{"Audit"}),
	}

	index := BuildIndex(policies, bindings)

	assert.True(t, index["C-0041"].Bound)
	assert.ElementsMatch(t, []string{"Deny", "Audit"}, index["C-0041"].Actions)
}

func TestEnrichSummary_AttachesStatus(t *testing.T) {
	controls := reportsummary.ControlSummaries{
		"C-0041": reportsummary.ControlSummary{ControlID: "C-0041"},
		"C-0016": reportsummary.ControlSummary{ControlID: "C-0016"},
	}
	index := map[string]*reportsummary.VAPEnforcementStatus{
		"C-0041": {PolicyName: "kubescape-c-0041", Bound: true, Actions: []string{"Warn"}},
	}

	EnrichSummary(controls, index)

	assert.NotNil(t, controls["C-0041"].VAPEnforcement)
	assert.Equal(t, "kubescape-c-0041", controls["C-0041"].VAPEnforcement.PolicyName)
	assert.True(t, controls["C-0041"].VAPEnforcement.Bound)
	// C-0016 has no VAP — field should remain nil
	assert.Nil(t, controls["C-0016"].VAPEnforcement)
}

func TestEnrichSummary_NoMatchingControl(t *testing.T) {
	// index has a controlId that isn't in the scan results — should not panic
	controls := reportsummary.ControlSummaries{
		"C-0041": reportsummary.ControlSummary{ControlID: "C-0041"},
	}
	index := map[string]*reportsummary.VAPEnforcementStatus{
		"C-9999": {PolicyName: "some-policy", Bound: true, Actions: []string{"Deny"}},
	}

	assert.NotPanics(t, func() {
		EnrichSummary(controls, index)
	})
	assert.Nil(t, controls["C-0041"].VAPEnforcement)
}
