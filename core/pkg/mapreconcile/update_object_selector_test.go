package mapreconcile

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	admission "k8s.io/api/admissionregistration/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestUpdateObjectSelectorKeepsUnseenLabelSetPossible(t *testing.T) {
	for _, bindingScoped := range []bool{false, true} {
		for _, namespaceKnown := range []bool{false, true} {
			for _, existingMatches := range []bool{false, true} {
				t.Run(fmt.Sprintf("binding=%v/namespaceKnown=%v/existingMatches=%v", bindingScoped, namespaceKnown, existingMatches), func(t *testing.T) {
					constraints := allPods()
					constraints.NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"team": "payments"}}
					constraints.ObjectSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"app": "worker"}}
					policyConstraints := constraints
					var bindingConstraints *admission.MatchResources
					if bindingScoped {
						policyConstraints, bindingConstraints = allPods(), constraints
					}
					idx, errs := NewIndex([]admission.MutatingAdmissionPolicy{policy("mutate", policyConstraints)},
						[]admission.MutatingAdmissionPolicyBinding{binding("bound", "mutate", bindingConstraints)})
					require.Empty(t, errs)
					resource := obj(func(o *ObjectInfo) {
						o.Operation = admission.Update
						o.Labels = map[string]string{"app": "web"}
						if existingMatches {
							o.Labels["app"] = "worker"
						}
						o.NamespaceLabelsKnown = namespaceKnown
						o.NamespaceLabels = map[string]string{"team": "payments"}
					})
					matches := idx.Matches(resource)
					require.Len(t, matches, 1, "the incoming UPDATE object can match even when the fetched object does not")
					require.Equal(t, namespaceKnown && existingMatches, matches[0].Determinable,
						"one matching label set proves the selector; a miss cannot rule out the unavailable other object")
				})
			}
		}
	}
}

func TestUpdateObjectSelectorUncertaintyDoesNotHideRuleExclusions(t *testing.T) {
	for _, exclude := range []bool{false, true} {
		constraints := allPods()
		constraints.ObjectSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"app": "worker"}}
		if exclude {
			constraints.ExcludeResourceRules = []admission.NamedRuleWithOperations{pods(admission.Update)}
		} else {
			constraints.ResourceRules[0].Operations = []admission.OperationType{admission.Create}
		}
		compiled, err := compileMatchResources(constraints)
		require.NoError(t, err)
		matched, known := compiled.matches(obj(func(o *ObjectInfo) {
			o.Operation = admission.Update
			o.Labels = map[string]string{"app": "web"}
		}))
		require.False(t, matched)
		require.True(t, known, "a proven resource-rule exclusion remains decisive despite an unknown incoming label set")
	}
}

func TestSingleObjectOperationsStillExcludeObjectSelectorMismatch(t *testing.T) {
	compiled, err := compileMatchResources(&admission.MatchResources{
		ObjectSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "worker"}},
	})
	require.NoError(t, err)
	for _, operation := range []admission.OperationType{admission.Create, admission.Delete} {
		matched, known := compiled.matches(obj(func(o *ObjectInfo) {
			o.Operation = operation
			o.Labels = map[string]string{"app": "web"}
		}))
		require.False(t, matched)
		require.True(t, known)
	}
}
