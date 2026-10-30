package mcpserver

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestMutationToolOmitsDefiniteExclusionsWithoutNamespaceInventory(t *testing.T) {
	for _, bindingScoped := range []bool{false, true} {
		for _, objectMatch := range []bool{false, true} {
			name := map[bool]string{false: "policy", true: "binding"}[bindingScoped] + map[bool]string{false: "/excluded", true: "/possible"}[objectMatch]
			t.Run(name, func(t *testing.T) {
				wanted := "worker"
				if objectMatch {
					wanted = "web"
				}
				constraints := allPodsMatchConstraints()
				constraints["namespaceSelector"] = map[string]any{"matchLabels": map[string]any{"team": "payments"}}
				constraints["objectSelector"] = map[string]any{"matchLabels": map[string]any{"app": wanted}}
				p := unstructuredMutatingPolicy("mutate", constraints)
				b := unstructuredMutatingPolicyBinding("bound", "mutate")
				if bindingScoped {
					p = unstructuredMutatingPolicy("mutate", allPodsMatchConstraints())
					require.NoError(t, unstructured.SetNestedMap(b.Object, constraints, "spec", "matchResources"))
				}
				ks := newMutatingPolicyTestServer(t, p, b, unstructuredTestPod("prod", "server", map[string]any{"app": "web"}))
				result := registeredToolResult(t, dispatchRegisteredTool(t, ks, "analyze_mutating_admission_policy_impact", map[string]any{
					"namespace": "prod", "name": "server", "resource": "pods", "api_version": "v1",
				}))
				require.False(t, result.IsError)
				var parsed struct {
					Matches []struct {
						Determinable bool `json:"determinable"`
					} `json:"matches"`
				}
				require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
				if objectMatch {
					require.Len(t, parsed.Matches, 1)
					require.False(t, parsed.Matches[0].Determinable)
				} else {
					require.Empty(t, parsed.Matches)
				}
			})
		}
	}
}

func TestMutationToolUpdateKeepsPossibleIncomingObjectMatch(t *testing.T) {
	for _, bindingScoped := range []bool{false, true} {
		name := map[bool]string{false: "policy", true: "binding"}[bindingScoped]
		t.Run(name, func(t *testing.T) {
			constraints := allPodsMatchConstraints()
			constraints["namespaceSelector"] = map[string]any{"matchLabels": map[string]any{"team": "payments"}}
			constraints["objectSelector"] = map[string]any{"matchLabels": map[string]any{"app": "worker"}}
			p := unstructuredMutatingPolicy("mutate", constraints)
			b := unstructuredMutatingPolicyBinding("bound", "mutate")
			if bindingScoped {
				p = unstructuredMutatingPolicy("mutate", allPodsMatchConstraints())
				require.NoError(t, unstructured.SetNestedMap(b.Object, constraints, "spec", "matchResources"))
			}
			ks := newMutatingPolicyTestServer(t, p, b, unstructuredTestPod("prod", "server", map[string]any{"app": "web"}))
			result := registeredToolResult(t, dispatchRegisteredTool(t, ks, "analyze_mutating_admission_policy_impact", map[string]any{
				"namespace": "prod", "name": "server", "resource": "pods", "api_version": "v1", "operation": "UPDATE",
			}))
			require.False(t, result.IsError)
			var parsed struct {
				Matches []struct {
					Determinable bool `json:"determinable"`
				} `json:"matches"`
			}
			require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
			require.Len(t, parsed.Matches, 1, "the fetched app=web object does not rule out an incoming app=worker UPDATE")
			require.False(t, parsed.Matches[0].Determinable)
		})
	}
}
