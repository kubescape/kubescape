package mapreconcile

import (
	"testing"

	"github.com/stretchr/testify/require"
	admission "k8s.io/api/admissionregistration/v1alpha1"
)

func TestEquivalentExclusionsRespectMatchCertainty(t *testing.T) {
	exact, equivalent := admission.Exact, admission.Equivalent
	clusterScope := admission.ClusterScope
	request := ObjectInfo{Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers", Name: "web", Namespace: "prod", Operation: admission.Update}
	include := rule([]string{"autoscaling"}, []string{"v2"}, []string{"horizontalpodautoscalers"}, admission.Update)
	exclude := rule([]string{"autoscaling"}, []string{"v1"}, []string{"horizontalpodautoscalers"}, admission.Update)
	for _, tc := range []struct {
		name                  string
		matchPolicy           *admission.MatchPolicyType
		edit                  func(*admission.MatchResources)
		matched, determinable bool
	}{
		{name: "default equivalent exclusion"},
		{name: "explicit equivalent exclusion", matchPolicy: &equivalent},
		{name: "exact does not widen exclusion", matchPolicy: &exact, matched: true, determinable: true},
		{name: "unrestricted include with possible exclusion", edit: func(m *admission.MatchResources) { m.ResourceRules = nil }},
		{name: "exact exclusion takes precedence", edit: func(m *admission.MatchResources) { m.ExcludeResourceRules[0].APIVersions = []string{"v2"} }, determinable: true},
		{name: "another operation cannot exclude", edit: func(m *admission.MatchResources) {
			m.ExcludeResourceRules[0].Operations = []admission.OperationType{admission.Create}
		}, matched: true, determinable: true},
		{name: "another resource cannot exclude", edit: func(m *admission.MatchResources) { m.ExcludeResourceRules[0].Resources = []string{"deployments"} }, matched: true, determinable: true},
		{name: "another name cannot exclude", edit: func(m *admission.MatchResources) { m.ExcludeResourceRules[0].ResourceNames = []string{"other"} }, matched: true, determinable: true},
		{name: "another scope cannot exclude", edit: func(m *admission.MatchResources) { m.ExcludeResourceRules[0].Scope = &clusterScope }, matched: true, determinable: true},
		{name: "matching restricted name may exclude", edit: func(m *admission.MatchResources) { m.ExcludeResourceRules[0].ResourceNames = []string{"web"} }},
		{name: "another subresource cannot exclude", edit: func(m *admission.MatchResources) {
			m.ExcludeResourceRules[0].Resources = []string{"horizontalpodautoscalers/status"}
		}, matched: true, determinable: true},
		{name: "wildcard resource may exclude", edit: func(m *admission.MatchResources) { m.ExcludeResourceRules[0].Resources = []string{"*"} }},
		{name: "cross-group exclusion may be equivalent", edit: func(m *admission.MatchResources) { m.ExcludeResourceRules[0].APIGroups = []string{"other.example.com"} }},
		{name: "definite include miss stays a non-match", edit: func(m *admission.MatchResources) { m.ResourceRules[0].Resources = []string{"deployments"} }, determinable: true},
		{name: "possible include and exclusion", edit: func(m *admission.MatchResources) { m.ResourceRules[0].APIVersions = []string{"v1"} }},
		{name: "no exclusion remains definite", edit: func(m *admission.MatchResources) { m.ExcludeResourceRules = nil }, matched: true, determinable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &admission.MatchResources{MatchPolicy: tc.matchPolicy, ResourceRules: []admission.NamedRuleWithOperations{*include.DeepCopy()}, ExcludeResourceRules: []admission.NamedRuleWithOperations{*exclude.DeepCopy()}}
			if tc.edit != nil {
				tc.edit(m)
			}
			compiled, err := compileMatchResources(m)
			require.NoError(t, err)
			matched, determinable := compiled.matches(request)
			require.Equal(t, tc.matched, matched)
			require.Equal(t, tc.determinable, determinable)
		})
	}
}

func TestMatchesEquivalentExclusionsAreReportedAsPossible(t *testing.T) {
	request := ObjectInfo{Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers", Name: "web", Namespace: "prod", Operation: admission.Update}
	include := rule([]string{"autoscaling"}, []string{"v2"}, []string{"horizontalpodautoscalers"}, admission.Update)
	exclude := rule([]string{"autoscaling"}, []string{"v1"}, []string{"horizontalpodautoscalers"}, admission.Update)
	for _, onBinding := range []bool{false, true} {
		t.Run(map[bool]string{false: "policy exclusion", true: "binding exclusion"}[onBinding], func(t *testing.T) {
			constraints := &admission.MatchResources{ResourceRules: []admission.NamedRuleWithOperations{include}}
			p := policy("mutate-hpa", constraints)
			b := binding("mutate-hpa-binding", p.Name, nil)
			if onBinding {
				b.Spec.MatchResources = &admission.MatchResources{ExcludeResourceRules: []admission.NamedRuleWithOperations{exclude}}
			} else {
				p.Spec.MatchConstraints.ExcludeResourceRules = []admission.NamedRuleWithOperations{exclude}
			}
			idx, errs := NewIndex([]admission.MutatingAdmissionPolicy{p}, []admission.MutatingAdmissionPolicyBinding{b})
			require.Empty(t, errs)
			matches := idx.Matches(request)
			require.Len(t, matches, 1, "unresolved exclusions must not hide a policy that might apply")
			require.False(t, matches[0].Determinable, "an equivalent exclusion cannot be resolved without the cluster's equivalence data")
		})
	}
}
