package opaprocessor

import (
	"context"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1unstructured "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// TestRunCELOnK8sBindingScope covers a live binding that carries
// spec.matchResources. Its paramRef applies only to the objects it binds; every
// other object the policy matches is evaluated against the bundled defaults,
// the same as when there is no binding at all.
//
// The fixture is C-0046 (insecure capabilities): the bundled configuration
// calls SETPCAP insecure, and the binding's permissive params allow it, so a
// pod passing means the binding's params reached it.
func TestRunCELOnK8sBindingScope(t *testing.T) {
	rule := &reporthandling.PolicyRule{
		PortalBase:   armotypes.PortalBase{Name: "cel-binding-scope"},
		RuleLanguage: reporthandling.CELLanguage,
	}
	pod := func(name, namespace string, podLabels map[string]any) map[string]any {
		metadata := map[string]any{"name": name, "namespace": namespace}
		if podLabels != nil {
			metadata["labels"] = podLabels
		}
		return map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata":   metadata,
			"spec": map[string]any{
				"containers": []any{map[string]any{
					"name":  "c",
					"image": "nginx",
					"securityContext": map[string]any{
						"capabilities": map[string]any{"add": []any{"SETPCAP"}},
					},
				}},
			},
		}
	}
	namespace := func(name, env string) map[string]any {
		return map[string]any{
			"apiVersion": "v1",
			"kind":       "Namespace",
			"metadata":   map[string]any{"name": name, "labels": map[string]any{"env": env}},
		}
	}
	scopedBinding := func(t *testing.T, controlID string, matchResources map[string]any) metav1unstructured.Unstructured {
		binding := paramRefBindingFor(t, controlID, map[string]any{"name": "permissive-config"})
		binding.Object["spec"].(map[string]any)["matchResources"] = matchResources
		return binding
	}
	processor := func(t *testing.T, binding metav1unstructured.Unstructured, namespaces ...map[string]any) *OPAProcessor {
		t.Helper()
		config := objectsenvelopes.NewObject(map[string]any{
			"apiVersion": "kubescape.io/v1",
			"kind":       "ControlConfiguration",
			"metadata":   map[string]any{"name": "permissive-config"},
			"settings":   map[string]any{"insecureCapabilities": []any{}},
		})
		require.NotNil(t, config)
		opap := paramRefProcessor(binding)
		opap.AllResources = map[string]workloadinterface.IMetadata{config.GetID(): config}
		opap.celNamespaceIndex = map[string]map[string]any{}
		for _, ns := range namespaces {
			opap.celNamespaceIndex[ns["metadata"].(map[string]any)["name"].(string)] = ns
		}
		return opap
	}
	failedNames := func(responses []reporthandling.RuleResponse) []string {
		var names []string
		for _, r := range responses {
			for _, obj := range r.AlertObject.K8SApiObjects {
				names = append(names, obj["metadata"].(map[string]any)["name"].(string))
			}
		}
		return names
	}

	t.Run("a binding from vap create-policy-binding, as the apiserver stores it, binds everything", func(t *testing.T) {
		// create-policy-binding writes `matchResources: {}`; the apiserver
		// defaults it to these three fields, none of which narrows anything.
		opap := processor(t, scopedBinding(t, "C-0046", map[string]any{
			"matchPolicy":       "Equivalent",
			"namespaceSelector": map[string]any{},
			"objectSelector":    map[string]any{},
		}))

		responses, _, err := opap.runCELOnK8s(context.Background(), rule, []map[string]any{pod("app", "default", nil)}, nil, "C-0046")
		require.NoError(t, err)
		assert.Empty(t, failedNames(responses), "the binding's params allow SETPCAP")
	})

	t.Run("namespaceSelector: bound namespaces get the binding's params, the rest the defaults", func(t *testing.T) {
		opap := processor(t, scopedBinding(t, "C-0046", map[string]any{
			"namespaceSelector": map[string]any{"matchLabels": map[string]any{"env": "prod"}},
		}), namespace("prod", "prod"), namespace("dev", "dev"))

		objects := []map[string]any{pod("in-prod", "prod", nil), pod("in-dev", "dev", nil)}
		responses, _, err := opap.runCELOnK8s(context.Background(), rule, objects, nil, "C-0046")
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"in-dev"}, failedNames(responses))
	})

	t.Run("namespaceSelector on an uncollected namespace leaves the verdict unknown", func(t *testing.T) {
		opap := processor(t, scopedBinding(t, "C-0046", map[string]any{
			"namespaceSelector": map[string]any{"matchLabels": map[string]any{"env": "prod"}},
		}))

		responses, outcome, err := opap.runCELOnK8s(context.Background(), rule, []map[string]any{pod("orphan", "missing", nil)}, nil, "C-0046")
		require.NoError(t, err)
		assert.Empty(t, responses, "neither params can be picked, so no verdict")
		require.Len(t, outcome.skipped, 1)
		assert.Contains(t, outcome.skipped[0].err.Error(), "namespaceSelector")
	})

	t.Run("objectSelector picks the bound objects by their own labels", func(t *testing.T) {
		opap := processor(t, scopedBinding(t, "C-0046", map[string]any{
			"objectSelector": map[string]any{"matchLabels": map[string]any{"tier": "trusted"}},
		}))

		objects := []map[string]any{
			pod("trusted", "default", map[string]any{"tier": "trusted"}),
			pod("untrusted", "default", nil),
		}
		responses, _, err := opap.runCELOnK8s(context.Background(), rule, objects, nil, "C-0046")
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"untrusted"}, failedNames(responses))
	})

	t.Run("resourceRules that leave pods out keep pods on the defaults", func(t *testing.T) {
		opap := processor(t, scopedBinding(t, "C-0046", map[string]any{
			"resourceRules": []any{map[string]any{
				"apiGroups": []any{"apps"}, "apiVersions": []any{"v1"},
				"resources": []any{"deployments"}, "operations": []any{"CREATE"},
			}},
		}))

		responses, _, err := opap.runCELOnK8s(context.Background(), rule, []map[string]any{pod("app", "default", nil)}, nil, "C-0046")
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"app"}, failedNames(responses))
	})

	t.Run("excludeResourceRules drop pods from the binding", func(t *testing.T) {
		opap := processor(t, scopedBinding(t, "C-0046", map[string]any{
			"excludeResourceRules": []any{map[string]any{
				"apiGroups": []any{""}, "apiVersions": []any{"v1"},
				"resources": []any{"pods"}, "operations": []any{"*"},
			}},
		}))

		responses, _, err := opap.runCELOnK8s(context.Background(), rule, []map[string]any{pod("app", "default", nil)}, nil, "C-0046")
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"app"}, failedNames(responses))
	})

	t.Run("a paramless control with a scoped binding is evaluated", func(t *testing.T) {
		opap := processor(t, scopedBinding(t, "C-0017", map[string]any{
			"namespaceSelector": map[string]any{"matchLabels": map[string]any{"env": "prod"}},
		}))

		responses, _, err := opap.runCELOnK8s(context.Background(), rule, []map[string]any{pod("app", "default", nil)}, nil, "C-0017")
		require.NoError(t, err)
		assert.Len(t, responses, 1, "C-0017 flags the mutable root filesystem whatever the binding's scope")
	})

	t.Run("a binding whose selector will not parse refuses the rule", func(t *testing.T) {
		opap := processor(t, scopedBinding(t, "C-0046", map[string]any{
			"objectSelector": map[string]any{"matchExpressions": []any{map[string]any{
				"key": "tier", "operator": "Bogus",
			}}},
		}))

		_, _, err := opap.runCELOnK8s(context.Background(), rule, []map[string]any{pod("app", "default", nil)}, nil, "C-0046")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "objectSelector")
	})
}
