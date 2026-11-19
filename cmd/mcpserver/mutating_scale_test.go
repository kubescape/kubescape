package mcpserver

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestAnalyzeMutatingAdmissionPolicyImpact_ScaleUsesSubresourceLabels(t *testing.T) {
	parentSelector := map[string]any{"matchLabels": map[string]any{"app": "server"}}
	for _, tc := range []struct {
		name          string
		subresource   string
		selector      map[string]any
		onBinding     bool
		clusterScoped bool
		scaleLabels   map[string]any
		determinable  bool
	}{
		{name: "policy selector cannot use Deployment labels", subresource: "scale", selector: parentSelector},
		{name: "binding selector cannot use Deployment labels", subresource: "scale", selector: parentSelector, onBinding: true},
		{name: "cluster scoped scale", subresource: "scale", selector: parentSelector, clusterScoped: true},
		{name: "absence selector matches Scale labels", subresource: "scale", selector: map[string]any{"matchExpressions": []any{
			map[string]any{"key": "app", "operator": "DoesNotExist"},
		}}, determinable: true},
		{name: "no object selector", subresource: "scale", determinable: true},
		{name: "empty object selector", subresource: "scale", selector: map[string]any{}, determinable: true},
		{name: "labels returned by scale endpoint", subresource: "scale", selector: map[string]any{"matchLabels": map[string]any{"scale-only": "yes"}}, scaleLabels: map[string]any{"scale-only": "yes"}, determinable: true},
		{name: "parent retains its labels", selector: parentSelector, determinable: true},
		{name: "status retains parent metadata", subresource: "status", selector: parentSelector, determinable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resource, kind, namespace := "deployments", "Deployment", "prod"
			if tc.clusterScoped {
				resource, kind, namespace = "widgets", "Widget", ""
			}
			ruleResource := resource
			if tc.subresource != "" {
				ruleResource += "/" + tc.subresource
			}
			constraints := matchConstraintsForResources("apps", "v1", ruleResource)
			constraints["namespaceSelector"] = map[string]any{"matchLabels": map[string]any{"team": "platform"}}
			policy := unstructuredMutatingPolicy("scale-policy", constraints,
				map[string]any{"patchType": "JSONPatch", "jsonPatch": map[string]any{"expression": `[JSONPatch{op: "replace", path: "/spec/replicas", value: 2}]`}})
			binding := unstructuredMutatingPolicyBinding("scale-binding", policy.GetName())
			if tc.selector != nil {
				if tc.onBinding {
					binding.Object["spec"].(map[string]any)["matchResources"] = map[string]any{"objectSelector": tc.selector}
				} else {
					constraints["objectSelector"] = tc.selector
				}
			}
			parent := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "apps/v1", "kind": kind,
				"metadata": map[string]any{"name": "server", "namespace": namespace, "labels": map[string]any{"app": "server"}},
			}}
			scale := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "autoscaling/v1", "kind": "Scale",
				"metadata": map[string]any{"name": "server", "namespace": namespace},
				"spec":     map[string]any{"replicas": int64(1)},
			}}
			if tc.scaleLabels != nil {
				scale.Object["metadata"].(map[string]any)["labels"] = tc.scaleLabels
			}
			ns := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "v1", "kind": "Namespace",
				"metadata": map[string]any{"name": "prod", "labels": map[string]any{"team": "platform"}},
			}}
			ksServer := newMutatingPolicyTestServer(t, policy, binding, parent, ns)
			dyn := ksServer.k8sClient.DynamicClient.(*dynamicfake.FakeDynamicClient)
			dyn.PrependReactor("get", resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
				assert.Equal(t, namespace, action.GetNamespace())
				if action.GetSubresource() == "scale" {
					return true, scale, nil
				}
				return false, nil, nil
			})

			result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_mutating_admission_policy_impact", map[string]any{
				"namespace": namespace, "name": "server", "api_group": "apps", "api_version": "v1",
				"resource": resource, "subresource": tc.subresource, "operation": "UPDATE", "cluster_scoped": tc.clusterScoped,
			}))
			require.False(t, result.IsError, toolResultText(t, result))
			var parsed struct {
				Matches []struct {
					Determinable bool `json:"determinable"`
				} `json:"matches"`
			}
			require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
			require.Len(t, parsed.Matches, 1)
			require.Equal(t, tc.determinable, parsed.Matches[0].Determinable)
		})
	}
}

func TestAnalyzeMutatingAdmissionPolicyImpact_ScaleReadErrorsAreClassified(t *testing.T) {
	gvr := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments/scale"}
	for _, tc := range []struct {
		name string
		err  error
		code ErrorCode
	}{
		{"forbidden", apierrors.NewForbidden(gvr.GroupResource(), "server", errors.New("denied")), ErrCodeRBACDenied},
		{"not found", apierrors.NewNotFound(gvr.GroupResource(), "server"), ErrCodeResourceNotFound},
		{"server error", apierrors.NewInternalError(errors.New("boom")), ErrCodeK8sClientError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ksServer := newMutatingPolicyTestServer(t)
			dyn := ksServer.k8sClient.DynamicClient.(*dynamicfake.FakeDynamicClient)
			dyn.PrependReactor("get", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
				assert.Equal(t, "scale", action.GetSubresource())
				return true, nil, tc.err
			})
			result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_mutating_admission_policy_impact", map[string]any{
				"namespace": "prod", "name": "server", "api_group": "apps", "api_version": "v1",
				"resource": "deployments", "subresource": "scale", "operation": "UPDATE",
			}))
			toolErr := toolErrorOf(t, result)
			require.Equal(t, tc.code, toolErr.Code)
			require.Contains(t, toolErr.Message, tc.err.Error())
		})
	}
}
