package cel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
)

func rule(groups, versions, resources []string) admissionregistrationv1.NamedRuleWithOperations {
	return admissionregistrationv1.NamedRuleWithOperations{
		RuleWithOperations: admissionregistrationv1.RuleWithOperations{
			Rule: admissionregistrationv1.Rule{
				APIGroups:   groups,
				APIVersions: versions,
				Resources:   resources,
			},
		},
	}
}

func vapWithConstraints(rules ...admissionregistrationv1.NamedRuleWithOperations) *VAP {
	return &VAP{matchConstraints: &admissionregistrationv1.MatchResources{ResourceRules: rules}}
}

func obj(apiVersion, kind string) map[string]any {
	return map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": map[string]any{"name": "x"}}
}

func TestVAPAppliesTo(t *testing.T) {
	// A C-0017-shaped constraint: core pods + apps workloads + batch jobs.
	pods := rule([]string{""}, []string{"v1"}, []string{"pods"})
	workloads := rule([]string{"apps"}, []string{"v1"}, []string{"deployments", "replicasets", "daemonsets", "statefulsets"})
	jobs := rule([]string{"batch"}, []string{"v1"}, []string{"jobs", "cronjobs"})
	v := vapWithConstraints(pods, workloads, jobs)

	cases := []struct {
		name       string
		apiVersion string
		kind       string
		want       bool
	}{
		{"pod matches core/pods", "v1", "Pod", true},
		{"deployment matches apps/deployments", "apps/v1", "Deployment", true},
		{"cronjob matches batch/cronjobs", "batch/v1", "CronJob", true},
		{"configmap is out of scope", "v1", "ConfigMap", false},
		{"deployment in wrong group is out of scope", "v1", "Deployment", false},
		{"pod in wrong version is out of scope", "v2", "Pod", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, v.appliesTo(obj(tc.apiVersion, tc.kind)))
		})
	}
}

func TestVAPAppliesToWildcards(t *testing.T) {
	any := vapWithConstraints(rule([]string{"*"}, []string{"*"}, []string{"*"}))
	assert.True(t, any.appliesTo(obj("v1", "Pod")))
	assert.True(t, any.appliesTo(obj("apps/v1", "Deployment")))
	assert.True(t, any.appliesTo(obj("networking.k8s.io/v1", "NetworkPolicy")))
}

func TestVAPAppliesToNoConstraintsEvaluates(t *testing.T) {
	// Missing matchConstraints is a malformed-policy edge; fall back to
	// evaluating rather than silently skipping everything.
	v := &VAP{}
	assert.True(t, v.appliesTo(obj("v1", "Pod")))
}

func TestVAPAppliesToExcludeRules(t *testing.T) {
	v := &VAP{matchConstraints: &admissionregistrationv1.MatchResources{
		ResourceRules:        []admissionregistrationv1.NamedRuleWithOperations{rule([]string{""}, []string{"v1"}, []string{"pods", "configmaps"})},
		ExcludeResourceRules: []admissionregistrationv1.NamedRuleWithOperations{rule([]string{""}, []string{"v1"}, []string{"configmaps"})},
	}}
	assert.True(t, v.appliesTo(obj("v1", "Pod")))
	assert.False(t, v.appliesTo(obj("v1", "ConfigMap")), "excluded resource must not apply")
}
