package mapreconcile

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admission "k8s.io/api/admissionregistration/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestMatches_ConnectRequestNeverMatchesObjectSelector covers a CONNECT
// request such as pods/exec. The apiserver admits it with the connect options
// (a PodExecOptions) as the object and no old object. Neither can carry
// labels, so a non-empty objectSelector never matches, whatever labels the
// pod itself has.
func TestMatches_ConnectRequestNeverMatchesObjectSelector(t *testing.T) {
	selectors := map[string]*metav1.LabelSelector{
		"matchLabels the pod has": {MatchLabels: map[string]string{"app": "web"}},
		"DoesNotExist the pod satisfies": {MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "debug", Operator: metav1.LabelSelectorOpDoesNotExist},
		}},
	}
	execRule := rule([]string{""}, []string{"v1"}, []string{"pods/exec"}, admission.Connect)
	exec := obj(func(o *ObjectInfo) {
		o.Name = "web"
		o.Subresource = "exec"
		o.Operation = admission.Connect
		o.Labels = map[string]string{"app": "web"}
	})

	for name, selector := range selectors {
		for _, onBinding := range []bool{false, true} {
			side := "policy"
			if onBinding {
				side = "binding"
			}
			t.Run(name+"/"+side, func(t *testing.T) {
				constraints := &admission.MatchResources{ResourceRules: []admission.NamedRuleWithOperations{execRule}}
				var bindingResources *admission.MatchResources
				if onBinding {
					bindingResources = &admission.MatchResources{ObjectSelector: selector}
				} else {
					constraints.ObjectSelector = selector
				}
				idx, errs := NewIndex([]admission.MutatingAdmissionPolicy{policy("mutate-exec", constraints)},
					[]admission.MutatingAdmissionPolicyBinding{binding("mutate-exec-binding", "mutate-exec", bindingResources)})
				require.Empty(t, errs)

				assert.Empty(t, idx.Matches(exec), "an objectSelector never matches a CONNECT request")
			})
		}
	}

	// Without an objectSelector the same CONNECT request still matches.
	idx, errs := NewIndex([]admission.MutatingAdmissionPolicy{policy("mutate-exec", &admission.MatchResources{
		ResourceRules: []admission.NamedRuleWithOperations{execRule},
	})}, []admission.MutatingAdmissionPolicyBinding{binding("mutate-exec-binding", "mutate-exec", nil)})
	require.Empty(t, errs)
	require.Len(t, idx.Matches(exec), 1)
	assert.True(t, idx.Matches(exec)[0].Determinable)
}
