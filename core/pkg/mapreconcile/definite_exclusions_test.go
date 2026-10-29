package mapreconcile

import (
	"testing"

	"github.com/stretchr/testify/require"
	admission "k8s.io/api/admissionregistration/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestMissingNamespaceLabelsDoNotHideDefiniteExclusions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*admission.MatchResources)
	}{
		{"object selector", func(m *admission.MatchResources) {
			m.ObjectSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"app": "worker"}}
		}},
		{"resource type", func(m *admission.MatchResources) {
			m.ResourceRules[0].Resources = []string{"configmaps"}
		}},
		{"operation", func(m *admission.MatchResources) {
			m.ResourceRules[0].Operations = []admission.OperationType{admission.Delete}
		}},
		{"resource name", func(m *admission.MatchResources) {
			m.ResourceRules[0].ResourceNames = []string{"another-pod"}
		}},
		{"scope", func(m *admission.MatchResources) {
			scope := admission.ClusterScope
			m.ResourceRules[0].Scope = &scope
		}},
		{"subresource", func(m *admission.MatchResources) {
			m.ResourceRules[0].Resources = []string{"pods/status"}
		}},
		{"explicit exclusion", func(m *admission.MatchResources) {
			m.ExcludeResourceRules = []admission.NamedRuleWithOperations{pods(admission.Create)}
		}},
		{"exact version", func(m *admission.MatchResources) {
			exact := admission.Exact
			m.MatchPolicy = &exact
			m.ResourceRules[0].APIVersions = []string{"v2"}
		}},
		{"exact API group", func(m *admission.MatchResources) {
			exact := admission.Exact
			m.MatchPolicy = &exact
			m.ResourceRules[0].APIGroups = []string{"example.io"}
		}},
		{"object label must be absent", func(m *admission.MatchResources) {
			m.ObjectSelector = &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "app", Operator: metav1.LabelSelectorOpDoesNotExist}}}
		}},
	} {
		for _, bindingScoped := range []bool{false, true} {
			t.Run(tc.name+map[bool]string{false: "/policy", true: "/binding"}[bindingScoped], func(t *testing.T) {
				constraints := allPods()
				constraints.NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"team": "payments"}}
				tc.change(constraints)
				resource := obj(func(o *ObjectInfo) {
					o.Name = "server"
					o.Labels = map[string]string{"app": "web"}
				})
				compiled, err := compileMatchResources(constraints)
				require.NoError(t, err)
				matched, known := compiled.matches(resource)
				require.False(t, matched)
				require.True(t, known, "a false conjunct decides the match even if another conjunct is unknown")

				policyConstraints := constraints
				var bindingConstraints *admission.MatchResources
				if bindingScoped {
					policyConstraints, bindingConstraints = allPods(), constraints
				}
				idx, errs := NewIndex([]admission.MutatingAdmissionPolicy{policy("mutate", policyConstraints)},
					[]admission.MutatingAdmissionPolicyBinding{binding("bound", "mutate", bindingConstraints)})
				require.Empty(t, errs)
				require.Empty(t, idx.Matches(resource), "a definitely excluded policy must not be returned as a possible mutation")
			})
		}
	}
}

func TestPossibleMutationsRemainUnknownWithoutNamespaceLabels(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*admission.MatchResources)
	}{
		{"otherwise matching", func(*admission.MatchResources) {}},
		{"matching object selector", func(m *admission.MatchResources) {
			m.ObjectSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}
		}},
		{"alternative include can match", func(m *admission.MatchResources) {
			other := pods(admission.Create)
			other.Resources = []string{"configmaps"}
			m.ResourceRules = append(m.ResourceRules, other)
		}},
		{"irrelevant exclusion", func(m *admission.MatchResources) {
			other := pods(admission.Delete)
			m.ExcludeResourceRules = []admission.NamedRuleWithOperations{other}
		}},
		{"unresolved include equivalence", func(m *admission.MatchResources) {
			m.ResourceRules[0].APIVersions = []string{"v2"}
		}},
		{"unresolved exclusion equivalence", func(m *admission.MatchResources) {
			other := pods(admission.Create)
			other.APIVersions = []string{"v2"}
			m.ExcludeResourceRules = []admission.NamedRuleWithOperations{other}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			constraints := allPods()
			constraints.NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"team": "payments"}}
			tc.change(constraints)
			idx, errs := NewIndex([]admission.MutatingAdmissionPolicy{policy("mutate", constraints)},
				[]admission.MutatingAdmissionPolicyBinding{binding("bound", "mutate", nil)})
			require.Empty(t, errs)
			matches := idx.Matches(obj(func(o *ObjectInfo) { o.Labels = map[string]string{"app": "web"} }))
			require.Len(t, matches, 1)
			require.False(t, matches[0].Determinable, "lack of a definite exclusion must not become a confirmed match")
		})
	}
}

func TestKnownNamespaceLabelsStillDecideMatchingPolicies(t *testing.T) {
	constraints := allPods()
	constraints.NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"team": "payments"}}
	idx, errs := NewIndex([]admission.MutatingAdmissionPolicy{policy("mutate", constraints)},
		[]admission.MutatingAdmissionPolicyBinding{binding("bound", "mutate", nil)})
	require.Empty(t, errs)
	for _, team := range []string{"payments", "other"} {
		resource := obj(func(o *ObjectInfo) {
			o.NamespaceLabelsKnown = true
			o.NamespaceLabels = map[string]string{"team": team}
		})
		matches := idx.Matches(resource)
		if team == "other" {
			require.Empty(t, matches)
		} else {
			require.Len(t, matches, 1)
			require.True(t, matches[0].Determinable)
		}
	}
}
