package mcpserver

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestMutationToolUsesImmutableNamespaceIdentity(t *testing.T) {
	for _, atBinding := range []bool{false, true} {
		for _, tc := range []struct {
			name      string
			selector  map[string]any
			namespace bool
			matches   bool
			known     bool
		}{
			{"name match without Namespace", map[string]any{"kubernetes.io/metadata.name": "prod"}, false, true, true},
			{"name exclusion without Namespace", map[string]any{"kubernetes.io/metadata.name": "dev"}, false, false, true},
			{"Namespace manifest omits automatic label", map[string]any{"kubernetes.io/metadata.name": "prod"}, true, true, true},
			{"Namespace mismatch with manifest", map[string]any{"kubernetes.io/metadata.name": "dev"}, true, false, true},
			{"unknown custom labels stay unknown", map[string]any{"team": "payments"}, false, true, false},
			{"known custom label absence excludes", map[string]any{"team": "payments"}, true, false, true},
		} {
			t.Run(tc.name+map[bool]string{false: "/policy", true: "/binding"}[atBinding], func(t *testing.T) {
				constraints := allPodsMatchConstraints()
				selector := map[string]any{"matchLabels": tc.selector}
				p := unstructuredMutatingPolicy("mutate", constraints)
				b := unstructuredMutatingPolicyBinding("bound", "mutate")
				if atBinding {
					require.NoError(t, unstructured.SetNestedMap(b.Object, map[string]any{"namespaceSelector": selector}, "spec", "matchResources"))
				} else {
					require.NoError(t, unstructured.SetNestedMap(p.Object, selector, "spec", "matchConstraints", "namespaceSelector"))
				}
				objects := []runtime.Object{p, b, unstructuredTestPod("prod", "server", nil)}
				if tc.namespace {
					objects = append(objects, &unstructured.Unstructured{Object: map[string]any{
						"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "prod"},
					}})
				}
				ksServer := newMutatingPolicyTestServer(t, objects...)
				result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_mutating_admission_policy_impact", map[string]any{
					"namespace": "prod", "name": "server", "api_version": "v1", "resource": "pods",
				}))
				require.False(t, result.IsError)
				var parsed struct {
					Supported bool `json:"supported"`
					Matches   []struct {
						PolicyName   string `json:"policy_name"`
						BindingName  string `json:"binding_name"`
						Determinable bool   `json:"determinable"`
					} `json:"matches"`
				}
				require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
				require.True(t, parsed.Supported)
				if !tc.matches {
					require.Empty(t, parsed.Matches)
					return
				}
				require.Len(t, parsed.Matches, 1)
				require.Equal(t, "mutate", parsed.Matches[0].PolicyName)
				require.Equal(t, "bound", parsed.Matches[0].BindingName)
				require.Equal(t, tc.known, parsed.Matches[0].Determinable)
			})
		}
	}
}
