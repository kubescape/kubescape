package mcpserver

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestMutatingPolicyImpactDoesNotConfirmEquivalentExclusions(t *testing.T) {
	for _, matchPolicy := range []string{"", "Equivalent", "Exact"} {
		t.Run("matchPolicy="+matchPolicy, func(t *testing.T) {
			rule := func(version string) map[string]any {
				return map[string]any{"apiGroups": []any{"autoscaling"}, "apiVersions": []any{version}, "resources": []any{"horizontalpodautoscalers"}, "operations": []any{"UPDATE"}}
			}
			constraints := map[string]any{
				"resourceRules":        []any{rule("v2")},
				"excludeResourceRules": []any{rule("v1")},
			}
			if matchPolicy != "" {
				constraints["matchPolicy"] = matchPolicy
			}
			policy := unstructuredMutatingPolicy("mutate-hpa", constraints, addLabelMutation())
			binding := unstructuredMutatingPolicyBinding("mutate-hpa-binding", policy.GetName())
			hpa := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "autoscaling/v2", "kind": "HorizontalPodAutoscaler",
				"metadata": map[string]any{"namespace": "prod", "name": "web"},
			}}
			matches := matchesFromToolResult(t, newMutatingPolicyTestServer(t, policy, binding, hpa), map[string]any{
				"namespace": "prod", "name": "web", "api_group": "autoscaling", "api_version": "v2", "resource": "horizontalpodautoscalers", "operation": "UPDATE",
			})
			require.Len(t, matches, 1)
			match := matches[0].(map[string]any)
			require.Equal(t, matchPolicy == "Exact", match["determinable"])
			require.Equal(t, "mutate-hpa", match["policy_name"])
		})
	}
}
