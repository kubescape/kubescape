package cel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
)

// TestMatchesResourceSubresourceHalves pins how a rule's resource entry is
// read when it carries a subresource. The scan evaluates objects only, whose
// subresource is empty, and the apiserver compares the two halves of an entry
// separately, so "*" in the subresource half matches the object itself while
// a named subresource never does.
func TestMatchesResourceSubresourceHalves(t *testing.T) {
	pods := []string{"pods"}
	for _, tc := range []struct {
		entry string
		want  bool
	}{
		{"pods", true},
		{"pods/*", true},
		{"*", true},
		{"*/*", true},
		{"pods/status", false},
		{"pods/exec", false},
		{"*/scale", false},
		{"*/status", false},
		{"deployments/*", false},
		{"Pods/*", true},
	} {
		t.Run(tc.entry, func(t *testing.T) {
			assert.Equal(t, tc.want, matchesResource([]string{tc.entry}, pods))
		})
	}
}

func TestMatchesResourceSubresourceWildcardUsesPluralCandidates(t *testing.T) {
	// The separator-insensitive comparison still applies to the resource
	// half, so a CRD rule written with its registered plural keeps matching.
	assert.True(t, matchesResource([]string{"worker-pools/*"}, []string{"workerpools"}))
	assert.False(t, matchesResource([]string{"worker-pools/status"}, []string{"workerpools"}))
}

// TestVAPAppliesToSubresourceWildcard covers policy matchConstraints written
// with "<resource>/*", a common way to reach a workload together with its
// scale and status subresources. Before, such a rule matched nothing the scan
// evaluates, so the policy was never run against those workloads and its
// control read as clean.
func TestVAPAppliesToSubresourceWildcard(t *testing.T) {
	v := vapWithConstraints(
		rule([]string{"apps"}, []string{"v1"}, []string{"deployments/*", "statefulsets/*"}),
		rule([]string{""}, []string{"v1"}, []string{"pods/ephemeralcontainers"}),
	)

	assert.True(t, v.AppliesTo(obj("apps/v1", "Deployment")), "deployments/* reaches the Deployment itself")
	assert.True(t, v.AppliesTo(obj("apps/v1", "StatefulSet")), "statefulsets/* reaches the StatefulSet itself")
	assert.False(t, v.AppliesTo(obj("apps/v1", "DaemonSet")), "a resource the rule does not name stays out of scope")
	assert.False(t, v.AppliesTo(obj("v1", "Pod")), "a named subresource never reaches the Pod itself")
}

func TestVAPAppliesToEverySubresourceWildcard(t *testing.T) {
	v := vapWithConstraints(rule([]string{"*"}, []string{"*"}, []string{"*/*"}))

	assert.True(t, v.AppliesTo(obj("v1", "Pod")))
	assert.True(t, v.AppliesTo(obj("apps/v1", "Deployment")))
	assert.True(t, v.AppliesTo(obj("rbac.authorization.k8s.io/v1", "ClusterRole")))
}

func TestVAPAppliesToOnlyNamedSubresources(t *testing.T) {
	v := vapWithConstraints(rule([]string{"*"}, []string{"*"}, []string{"*/scale", "*/status"}))

	assert.False(t, v.AppliesTo(obj("apps/v1", "Deployment")), "*/scale names a subresource, not the Deployment")
	assert.False(t, v.AppliesTo(obj("v1", "Pod")))
}

// TestVAPAppliesToExcludedSubresourceWildcard is the exclusion side: at
// admission an excludeResourceRules entry of "pods/*" keeps the policy off
// pods entirely, so the scan must not evaluate them and report failures the
// cluster would never raise.
func TestVAPAppliesToExcludedSubresourceWildcard(t *testing.T) {
	v := &VAP{matchConstraints: &admissionregistrationv1.MatchResources{
		ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
			rule([]string{""}, []string{"v1"}, []string{"pods", "configmaps"}),
		},
		ExcludeResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
			rule([]string{""}, []string{"v1"}, []string{"pods/*"}),
		},
	}}

	assert.False(t, v.AppliesTo(obj("v1", "Pod")), "pods/* in excludeResourceRules exempts pods")
	assert.True(t, v.AppliesTo(obj("v1", "ConfigMap")), "the exclusion does not reach other resources")
}

func TestVAPAppliesToExcludedNamedSubresourceKeepsTheObject(t *testing.T) {
	v := &VAP{matchConstraints: &admissionregistrationv1.MatchResources{
		ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
			rule([]string{""}, []string{"v1"}, []string{"pods"}),
		},
		ExcludeResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
			rule([]string{""}, []string{"v1"}, []string{"pods/status", "*/scale"}),
		},
	}}

	assert.True(t, v.AppliesTo(obj("v1", "Pod")), "excluding a subresource does not exclude the Pod itself")
}
