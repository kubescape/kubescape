package vapreconcile

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// TestCoverageHonorsSubresourceWildcardRules checks the coverage report for a
// binding whose matchResources name resources as "<resource>/*". The
// apiserver reads that as the resource and every one of its subresources, so
// the binding enforces against the object itself; an exclusion written that
// way keeps the object out.
func TestCoverageHonorsSubresourceWildcardRules(t *testing.T) {
	const notMatched = "binding resourceRules/excludeResourceRules do not match the resource"

	for _, tc := range []struct {
		name           string
		matchResources map[string]any
		resource       ResourceInfo
		covered        bool
		reason         string
	}{
		{
			name:           "deployments/* covers a deployment",
			matchResources: map[string]any{"resourceRules": []any{resourceRule("apps", "v1", "deployments/*", nil)}},
			resource:       rulesDeployment,
			covered:        true,
		},
		{
			name:           "deployments/* does not cover a pod",
			matchResources: map[string]any{"resourceRules": []any{resourceRule("apps", "v1", "deployments/*", nil)}},
			resource:       rulesPod,
			reason:         notMatched,
		},
		{
			name:           "*/* covers a cluster-scoped resource",
			matchResources: map[string]any{"resourceRules": []any{resourceRule("*", "*", "*/*", nil)}},
			resource:       rulesClusterRol,
			covered:        true,
		},
		{
			name:           "*/scale names only a subresource",
			matchResources: map[string]any{"resourceRules": []any{resourceRule("*", "*", "*/scale", nil)}},
			resource:       rulesDeployment,
			reason:         notMatched,
		},
		{
			name:           "excluding pods/* drops the pod",
			matchResources: map[string]any{"excludeResourceRules": []any{resourceRule("", "v1", "pods/*", nil)}},
			resource:       rulesPod,
			reason:         notMatched,
		},
		{
			name:           "excluding pods/status keeps the pod",
			matchResources: map[string]any{"excludeResourceRules": []any{resourceRule("", "v1", "pods/status", nil)}},
			resource:       rulesPod,
			covered:        true,
		},
		{
			name:           "excluding pods/* leaves deployments covered",
			matchResources: map[string]any{"excludeResourceRules": []any{resourceRule("", "v1", "pods/*", nil)}},
			resource:       rulesDeployment,
			covered:        true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := rulesCoverage(t, []unstructured.Unstructured{bindingWithMatchResources("b", tc.matchResources)}, tc.resource, nil)
			assert.Equal(t, tc.covered, rc.Covered)
			assert.Equal(t, tc.reason, rc.Reason)
		})
	}
}
