package mapreconcile

import (
	"testing"

	"github.com/stretchr/testify/require"
	admission "k8s.io/api/admissionregistration/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func namespaceNameSelector(operator metav1.LabelSelectorOperator, values ...string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
		Key: corev1.LabelMetadataName, Operator: operator, Values: values,
	}}}
}

func TestMutationNamespaceNameSelectorsWithoutInventory(t *testing.T) {
	for _, tc := range []struct {
		name     string
		selector *metav1.LabelSelector
		matched  bool
	}{
		{"matching label", &metav1.LabelSelector{MatchLabels: map[string]string{corev1.LabelMetadataName: "prod"}}, true},
		{"different label", &metav1.LabelSelector{MatchLabels: map[string]string{corev1.LabelMetadataName: "dev"}}, false},
		{"In includes namespace", namespaceNameSelector(metav1.LabelSelectorOpIn, "dev", "prod"), true},
		{"In excludes namespace", namespaceNameSelector(metav1.LabelSelectorOpIn, "dev"), false},
		{"NotIn includes namespace", namespaceNameSelector(metav1.LabelSelectorOpNotIn, "dev"), true},
		{"NotIn excludes namespace", namespaceNameSelector(metav1.LabelSelectorOpNotIn, "prod"), false},
		{"automatic label exists", namespaceNameSelector(metav1.LabelSelectorOpExists), true},
		{"automatic label cannot be absent", namespaceNameSelector(metav1.LabelSelectorOpDoesNotExist), false},
	} {
		for _, atBinding := range []bool{false, true} {
			t.Run(tc.name+map[bool]string{false: "/policy", true: "/binding"}[atBinding], func(t *testing.T) {
				constraint := allPods()
				var bindingScope *admission.MatchResources
				if atBinding {
					bindingScope = &admission.MatchResources{NamespaceSelector: tc.selector}
				} else {
					constraint.NamespaceSelector = tc.selector
				}
				idx, errs := NewIndex([]admission.MutatingAdmissionPolicy{policy("mutate", constraint)},
					[]admission.MutatingAdmissionPolicyBinding{binding("bound", "mutate", bindingScope)})
				require.Empty(t, errs)
				matches := idx.Matches(obj(func(o *ObjectInfo) { o.Namespace = "prod" }))
				if !tc.matched {
					require.Empty(t, matches, "a known namespace-name mismatch must be a definite exclusion")
					return
				}
				require.Len(t, matches, 1)
				require.True(t, matches[0].Determinable, "the namespace name does not require a Namespace listing")
			})
		}
	}
}

func TestMutationNamespaceIdentityOverridesCollectedLabel(t *testing.T) {
	for _, inventory := range []map[string]string{nil, {}, {corev1.LabelMetadataName: "dev"}} {
		constraint := allPods()
		constraint.NamespaceSelector = namespaceNameSelector(metav1.LabelSelectorOpIn, "prod")
		compiled, err := compileMatchResources(constraint)
		require.NoError(t, err)
		resource := obj(func(o *ObjectInfo) {
			o.Namespace = "prod"
			o.NamespaceLabels = inventory
			o.NamespaceLabelsKnown = true
		})
		matched, known := compiled.matches(resource)
		require.True(t, known)
		require.True(t, matched, "omitted or conflicting automatic labels must use the namespace identity")
		if inventory != nil {
			_, inserted := inventory[corev1.LabelMetadataName]
			if inserted {
				require.Equal(t, "dev", inventory[corev1.LabelMetadataName])
			} else {
				require.Empty(t, inventory)
			}
		}
	}
}

func TestMutationNamespaceObjectsUseTheirOwnName(t *testing.T) {
	for _, name := range []string{"prod", "dev"} {
		compiled, err := compileMatchResources(&admission.MatchResources{
			NamespaceSelector: namespaceNameSelector(metav1.LabelSelectorOpIn, "prod"),
		})
		require.NoError(t, err)
		resource := ObjectInfo{
			Name: name, Resource: "namespaces", Group: "", Version: "v1", Operation: admission.Create,
			ClusterScoped: true, IsNamespaceObject: true,
		}
		matched, known := compiled.matches(resource)
		require.True(t, known)
		require.Equal(t, name == "prod", matched)
		require.Nil(t, resource.Labels, "the automatic label must not be written into the resource")
	}
}

func TestMutationMixedNamespaceRequirementsRemainConservative(t *testing.T) {
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{
		corev1.LabelMetadataName: "prod", "team": "payments",
	}}
	compiled, err := compileMatchResources(&admission.MatchResources{NamespaceSelector: selector})
	require.NoError(t, err)
	for _, tc := range []struct {
		name      string
		namespace string
		labels    map[string]string
		collected bool
		matched   bool
		known     bool
	}{
		{"missing custom labels", "prod", nil, false, false, false},
		{"partial custom labels are not trusted", "prod", map[string]string{"team": "payments"}, false, false, false},
		{"known namespace mismatch wins", "dev", nil, false, false, true},
		{"collected matching custom labels", "prod", map[string]string{"team": "payments"}, true, true, true},
		{"collected conflicting custom labels", "prod", map[string]string{"team": "other"}, true, false, true},
		{"collected absent custom labels", "prod", nil, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resource := obj(func(o *ObjectInfo) {
				o.Namespace = tc.namespace
				o.NamespaceLabels = tc.labels
				o.NamespaceLabelsKnown = tc.collected
			})
			matched, known := compiled.matches(resource)
			require.Equal(t, tc.matched, matched)
			require.Equal(t, tc.known, known)
		})
	}
}

func TestMutationInferredNamespaceDoesNotBypassOtherConstraints(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*admission.MatchResources)
	}{
		{"object selector", func(m *admission.MatchResources) {
			m.ObjectSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"mutate": "yes"}}
		}},
		{"resource exclusions", func(m *admission.MatchResources) {
			m.ExcludeResourceRules = []admission.NamedRuleWithOperations{pods(admission.Create)}
		}},
		{"operation mismatch", func(m *admission.MatchResources) {
			m.ResourceRules = []admission.NamedRuleWithOperations{pods(admission.Delete)}
		}},
		{"named resource mismatch", func(m *admission.MatchResources) {
			m.ResourceRules[0].ResourceNames = []string{"another"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			constraint := allPods()
			constraint.NamespaceSelector = namespaceNameSelector(metav1.LabelSelectorOpIn, "prod")
			tc.change(constraint)
			compiled, err := compileMatchResources(constraint)
			require.NoError(t, err)
			matched, known := compiled.matches(obj(func(o *ObjectInfo) { o.Namespace = "prod" }))
			require.True(t, known)
			require.False(t, matched)
		})
	}
}

func TestMutationPolicyAndBindingNamespaceSelectorsIntersect(t *testing.T) {
	constraint := allPods()
	constraint.NamespaceSelector = namespaceNameSelector(metav1.LabelSelectorOpIn, "prod")
	scope := &admission.MatchResources{NamespaceSelector: namespaceNameSelector(metav1.LabelSelectorOpIn, "dev")}
	idx, errs := NewIndex([]admission.MutatingAdmissionPolicy{policy("mutate", constraint)},
		[]admission.MutatingAdmissionPolicyBinding{binding("bound", "mutate", scope)})
	require.Empty(t, errs)
	for _, namespace := range []string{"prod", "dev", "other"} {
		require.Empty(t, idx.Matches(obj(func(o *ObjectInfo) { o.Namespace = namespace })))
	}
}

func TestMutationNamespaceInferenceKeepsOtherUncertainty(t *testing.T) {
	constraint := allPods()
	constraint.NamespaceSelector = namespaceNameSelector(metav1.LabelSelectorOpIn, "prod")
	p := policy("conditional", constraint)
	p.Spec.MatchConditions = []admission.MatchCondition{{Name: "gate", Expression: "object.metadata.name == 'server'"}}
	idx, errs := NewIndex([]admission.MutatingAdmissionPolicy{p},
		[]admission.MutatingAdmissionPolicyBinding{binding("bound", p.Name, nil)})
	require.Empty(t, errs)
	matches := idx.Matches(obj(func(o *ObjectInfo) { o.Namespace = "prod" }))
	require.Len(t, matches, 1)
	require.False(t, matches[0].Determinable, "knowing the namespace cannot resolve an unevaluated CEL gate")
	require.Empty(t, idx.Matches(obj(func(o *ObjectInfo) { o.Namespace = "dev" })))
}

func TestMutationNamespaceInferenceDoesNotApplyToObjectSelector(t *testing.T) {
	compiled, err := compileMatchResources(&admission.MatchResources{
		ObjectSelector: &metav1.LabelSelector{MatchLabels: map[string]string{corev1.LabelMetadataName: "prod"}},
	})
	require.NoError(t, err)
	matched, known := compiled.matches(obj(func(o *ObjectInfo) { o.Namespace = "prod" }))
	require.True(t, known)
	require.False(t, matched, "Pod labels must never inherit namespace labels")
}

func TestMutationNameSelectorDoesNotExemptOtherClusterScopedKinds(t *testing.T) {
	compiled, err := compileMatchResources(&admission.MatchResources{
		NamespaceSelector: namespaceNameSelector(metav1.LabelSelectorOpIn, "prod"),
	})
	require.NoError(t, err)
	resource := ObjectInfo{
		Name: "dev", Resource: "clusterroles", Group: "rbac.authorization.k8s.io", Version: "v1",
		Operation: admission.Create, ClusterScoped: true,
	}
	matched, known := compiled.matches(resource)
	require.True(t, matched, "a ClusterRole's name is not a namespace identity")
	require.True(t, known)
}

func TestMutationNameInferenceDoesNotResolveAPIVersionEquivalence(t *testing.T) {
	constraint := allPods()
	constraint.NamespaceSelector = namespaceNameSelector(metav1.LabelSelectorOpIn, "prod")
	compiled, err := compileMatchResources(constraint)
	require.NoError(t, err)
	resource := obj(func(o *ObjectInfo) { o.Namespace = "prod"; o.Version = "v2" })
	matched, known := compiled.matches(resource)
	require.False(t, matched)
	require.False(t, known, "namespace certainty cannot resolve an unknown equivalent resource version")
}
