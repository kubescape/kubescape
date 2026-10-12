package mcpserver

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
)

func newTestMCPServerWithK8s(k8sClient *k8sinterface.KubernetesApi) *KubescapeMcpserver {
	ksServer := &KubescapeMcpserver{
		s: server.NewMCPServer(
			"kubescape-test",
			"test",
			server.WithToolCapabilities(false),
			server.WithRecovery(),
		),
		k8sClient: k8sClient,
	}
	createAdvancedTools(ksServer)
	return ksServer
}

// TestScanResourceSlice_EmptyResultMarshalsAsEmptyArray guards against a
// nil-slice regression: when the cluster has zero matching resources, the
// "resources" field must serialize as [], not JSON null. A null there fails
// MCP clients that validate the response against the tool's declared array
// schema.
func TestScanResourceSlice_EmptyResultMarshalsAsEmptyArray(t *testing.T) {
	listKinds := map[schema.GroupVersionResource]string{
		{Group: "", Version: "v1", Resource: "pods"}: "PodList",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds)
	ksServer := newTestMCPServerWithK8s(&k8sinterface.KubernetesApi{DynamicClient: dyn})

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "scan_resource_slice", map[string]any{
		"resource_kind": "pods",
	}))
	require.False(t, result.IsError)

	raw := toolResultText(t, result)
	require.JSONEq(t, `{"resources":[],"continue":"","count":0}`, raw)
}

// TestScanResourceSlice_UnsupportedKindReturnsError guards against a silent
// fallback to core/v1 for resource kinds the tool does not explicitly map
// (e.g. "jobs"). Falling back would send a request to the wrong API group and
// surface the cluster's "resource not found" rejection as an opaque list
// failure, indistinguishable from a connectivity problem.
func TestScanResourceSlice_UnsupportedKindReturnsError(t *testing.T) {
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{})
	ksServer := newTestMCPServerWithK8s(&k8sinterface.KubernetesApi{DynamicClient: dyn})

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "scan_resource_slice", map[string]any{
		"resource_kind": "jobs",
	}))
	require.True(t, result.IsError)
	var toolErr ToolError
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
	require.Equal(t, ErrCodeUnsupportedResource, toolErr.Code)
	require.Contains(t, toolErr.Message, `unsupported resource kind "jobs"`)
	require.Contains(t, toolErr.Message, "pods")
	require.Contains(t, toolErr.Message, "deployments")
	require.Contains(t, toolErr.Message, "daemonsets")
	require.Contains(t, toolErr.Message, "statefulsets")
	require.Equal(t, "jobs", toolErr.Details["kind"])
}

// TestScanResourceSlice_UnsupportedKindReturnsErrorWithoutClusterConfig
// guards against the unsupported-kind check being reordered behind
// getK8sClient(): with no pre-populated k8sClient and no reachable cluster
// config, the tool must still report the unsupported kind rather than
// masking it behind "failed to get k8s client".
func TestScanResourceSlice_UnsupportedKindReturnsErrorWithoutClusterConfig(t *testing.T) {
	origLoadK8sConfig := loadK8sConfig
	t.Cleanup(func() { loadK8sConfig = origLoadK8sConfig })
	loadK8sConfig = func() error { return errors.New("no kubeconfig") }

	ksServer := &KubescapeMcpserver{
		s: server.NewMCPServer(
			"kubescape-test",
			"test",
			server.WithToolCapabilities(false),
			server.WithRecovery(),
		),
	}
	createAdvancedTools(ksServer)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "scan_resource_slice", map[string]any{
		"resource_kind": "jobs",
	}))
	require.True(t, result.IsError)
	var toolErr ToolError
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
	require.Equal(t, ErrCodeUnsupportedResource, toolErr.Code)
	require.Contains(t, toolErr.Message, `unsupported resource kind "jobs"`)
}

func TestScanResourceSlice_ArgumentValidation(t *testing.T) {
	dyn := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	ksServer := newTestMCPServerWithK8s(&k8sinterface.KubernetesApi{DynamicClient: dyn})

	tests := []struct {
		name         string
		arguments    map[string]any
		expectedCode ErrorCode
		expectedArg  string
	}{
		{
			name:         "missing resource_kind",
			arguments:    map[string]any{},
			expectedCode: ErrCodeInvalidArgument,
			expectedArg:  "resource_kind",
		},
		{
			name:         "empty resource_kind",
			arguments:    map[string]any{"resource_kind": "   "},
			expectedCode: ErrCodeInvalidArgument,
			expectedArg:  "resource_kind",
		},
		{
			name:         "non-string resource_kind",
			arguments:    map[string]any{"resource_kind": 123},
			expectedCode: ErrCodeInvalidArgument,
			expectedArg:  "resource_kind",
		},
		{
			name:         "invalid namespace type",
			arguments:    map[string]any{"resource_kind": "pods", "namespace": 42},
			expectedCode: ErrCodeInvalidArgument,
			expectedArg:  "namespace",
		},
		{
			name:         "invalid continue type",
			arguments:    map[string]any{"resource_kind": "pods", "continue": true},
			expectedCode: ErrCodeInvalidArgument,
			expectedArg:  "continue",
		},
		{
			name:         "non-number limit",
			arguments:    map[string]any{"resource_kind": "pods", "limit": "twenty"},
			expectedCode: ErrCodeInvalidArgument,
			expectedArg:  "limit",
		},
		{
			name:         "negative limit",
			arguments:    map[string]any{"resource_kind": "pods", "limit": float64(-5)},
			expectedCode: ErrCodeInvalidArgument,
			expectedArg:  "limit",
		},
		{
			name:         "fractional limit",
			arguments:    map[string]any{"resource_kind": "pods", "limit": 2.5},
			expectedCode: ErrCodeInvalidArgument,
			expectedArg:  "limit",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "scan_resource_slice", tc.arguments))
			require.True(t, result.IsError)
			var toolErr ToolError
			require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
			require.Equal(t, tc.expectedCode, toolErr.Code)
			require.Equal(t, tc.expectedArg, toolErr.Details["argument"])
		})
	}
}

func TestEvaluateCelRule_ValidationAndEvaluation(t *testing.T) {
	ksServer := &KubescapeMcpserver{
		s: server.NewMCPServer("test", "v1", server.WithToolCapabilities(false), server.WithRecovery()),
	}
	createAdvancedTools(ksServer)

	t.Run("missing cel_expression", func(t *testing.T) {
		result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "evaluate_cel_rule", map[string]any{
			"resource_json": `{"metadata":{"name":"test"}}`,
		}))
		require.True(t, result.IsError)
		var toolErr ToolError
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
		require.Equal(t, ErrCodeInvalidArgument, toolErr.Code)
		require.Equal(t, "cel_expression", toolErr.Details["argument"])
	})

	t.Run("missing resource_json", func(t *testing.T) {
		result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "evaluate_cel_rule", map[string]any{
			"cel_expression": `object.metadata.name == "test"`,
		}))
		require.True(t, result.IsError)
		var toolErr ToolError
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
		require.Equal(t, ErrCodeInvalidArgument, toolErr.Code)
		require.Equal(t, "resource_json", toolErr.Details["argument"])
	})

	t.Run("malformed resource_json", func(t *testing.T) {
		result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "evaluate_cel_rule", map[string]any{
			"cel_expression": `object.metadata.name == "test"`,
			"resource_json":  `{invalid json`,
		}))
		require.True(t, result.IsError)
		var toolErr ToolError
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
		require.Equal(t, ErrCodeInvalidArgument, toolErr.Code)
		require.Equal(t, "resource_json", toolErr.Details["argument"])
	})

	t.Run("input exceeds size limits", func(t *testing.T) {
		hugeJSON := `{"data":"` + strings.Repeat("x", 1000001) + `"}`
		result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "evaluate_cel_rule", map[string]any{
			"cel_expression": "true",
			"resource_json":  hugeJSON,
		}))
		require.True(t, result.IsError)
		var toolErr ToolError
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
		require.Equal(t, ErrCodeInvalidArgument, toolErr.Code)
		require.Contains(t, toolErr.Message, "exceeds size limits")
	})

	t.Run("padded whitespace cel_expression exceeds raw size limit", func(t *testing.T) {
		paddedExpr := strings.Repeat(" ", 10001) + "true"
		result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "evaluate_cel_rule", map[string]any{
			"cel_expression": paddedExpr,
			"resource_json":  `{"metadata":{"name":"test"}}`,
		}))
		require.True(t, result.IsError)
		var toolErr ToolError
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
		require.Equal(t, ErrCodeInvalidArgument, toolErr.Code)
		require.Equal(t, "cel_expression", toolErr.Details["argument"])
		require.Contains(t, toolErr.Message, "exceeds size limits")
	})

	t.Run("invalid CEL expression syntax", func(t *testing.T) {
		result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "evaluate_cel_rule", map[string]any{
			"cel_expression": "invalid == syntax %%%",
			"resource_json":  `{"metadata":{"name":"test"}}`,
		}))
		require.True(t, result.IsError)
		var toolErr ToolError
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
		require.Equal(t, ErrCodeInvalidArgument, toolErr.Code)
		require.Equal(t, "cel_expression", toolErr.Details["argument"])
		require.Contains(t, toolErr.Message, "failed to compile CEL expression")
	})

	t.Run("successful evaluation true", func(t *testing.T) {
		result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "evaluate_cel_rule", map[string]any{
			"cel_expression": `object.metadata.name == "my-service"`,
			"resource_json":  `{"metadata":{"name":"my-service"}}`,
		}))
		require.False(t, result.IsError)
		require.Equal(t, "true", toolResultText(t, result))
	})

	t.Run("successful evaluation false", func(t *testing.T) {
		result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "evaluate_cel_rule", map[string]any{
			"cel_expression": `object.metadata.name == "other"`,
			"resource_json":  `{"metadata":{"name":"my-service"}}`,
		}))
		require.False(t, result.IsError)
		require.Equal(t, "false", toolResultText(t, result))
	})
}

func TestDryRunRemediation_ArgumentValidation(t *testing.T) {
	dyn := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	ksServer := newTestMCPServerWithK8s(&k8sinterface.KubernetesApi{DynamicClient: dyn})

	validPatch := `{"spec":{"containers":[{"name":"app","securityContext":{"readOnlyRootFilesystem":true}}]}}`

	tests := []struct {
		name         string
		arguments    map[string]any
		expectedCode ErrorCode
		expectedArg  string
	}{
		{
			name: "missing resource_kind",
			arguments: map[string]any{
				"resource_name": "app",
				"patch_json":    validPatch,
			},
			expectedCode: ErrCodeInvalidArgument,
			expectedArg:  "resource_kind",
		},
		{
			name: "missing resource_name",
			arguments: map[string]any{
				"resource_kind": "pods",
				"patch_json":    validPatch,
			},
			expectedCode: ErrCodeInvalidArgument,
			expectedArg:  "resource_name",
		},
		{
			name: "missing patch_json",
			arguments: map[string]any{
				"resource_kind": "pods",
				"resource_name": "app",
			},
			expectedCode: ErrCodeInvalidArgument,
			expectedArg:  "patch_json",
		},
		{
			name: "invalid namespace type",
			arguments: map[string]any{
				"resource_kind": "pods",
				"resource_name": "app",
				"patch_json":    validPatch,
				"namespace":     1234,
			},
			expectedCode: ErrCodeInvalidArgument,
			expectedArg:  "namespace",
		},
		{
			name: "malformed patch_json",
			arguments: map[string]any{
				"resource_kind": "pods",
				"resource_name": "app",
				"patch_json":    "{not valid json",
			},
			expectedCode: ErrCodeInvalidArgument,
			expectedArg:  "patch_json",
		},
		{
			name: "oversized patch_json",
			arguments: map[string]any{
				"resource_kind": "pods",
				"resource_name": "app",
				"patch_json":    `{"data":"` + strings.Repeat("a", 1000001) + `"}`,
			},
			expectedCode: ErrCodeInvalidArgument,
			expectedArg:  "patch_json",
		},
		{
			name: "padded patch_json exceeds raw size limit",
			arguments: map[string]any{
				"resource_kind": "pods",
				"resource_name": "app",
				"patch_json":    strings.Repeat(" ", 1000001) + validPatch,
			},
			expectedCode: ErrCodeInvalidArgument,
			expectedArg:  "patch_json",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "dry_run_remediation", tc.arguments))
			require.True(t, result.IsError)
			var toolErr ToolError
			require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
			require.Equal(t, tc.expectedCode, toolErr.Code)
			require.Equal(t, tc.expectedArg, toolErr.Details["argument"])
		})
	}
}

func TestDryRunRemediation_UnsupportedKind(t *testing.T) {
	dyn := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	ksServer := newTestMCPServerWithK8s(&k8sinterface.KubernetesApi{DynamicClient: dyn})

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "dry_run_remediation", map[string]any{
		"resource_kind": "secrets",
		"resource_name": "my-secret",
		"patch_json":    `{"data":{}}`,
	}))
	require.True(t, result.IsError)
	var toolErr ToolError
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
	require.Equal(t, ErrCodeUnsupportedResource, toolErr.Code)
	require.Contains(t, toolErr.Message, `security barrier: patching kind "secrets" is not permitted`)
	require.Equal(t, "secrets", toolErr.Details["kind"])
}

func TestDryRunRemediation_UnsupportedKindWithoutClusterConfig(t *testing.T) {
	origLoadK8sConfig := loadK8sConfig
	t.Cleanup(func() { loadK8sConfig = origLoadK8sConfig })
	loadK8sConfig = func() error { return errors.New("no kubeconfig") }

	ksServer := &KubescapeMcpserver{
		s: server.NewMCPServer("test", "v1", server.WithToolCapabilities(false), server.WithRecovery()),
	}
	createAdvancedTools(ksServer)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "dry_run_remediation", map[string]any{
		"resource_kind": "clusterroles",
		"resource_name": "admin",
		"patch_json":    `{"rules":[]}`,
	}))
	require.True(t, result.IsError)
	var toolErr ToolError
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
	require.Equal(t, ErrCodeUnsupportedResource, toolErr.Code)
	require.Contains(t, toolErr.Message, `security barrier: patching kind "clusterroles" is not permitted`)
}

func TestDryRunRemediation_Success(t *testing.T) {
	pod := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]any{
				"name":      "nginx-pod",
				"namespace": "default",
			},
			"spec": map[string]any{
				"containers": []any{
					map[string]any{
						"name":  "nginx",
						"image": "nginx:1.20",
					},
				},
			},
		},
	}
	patchJSON := `{"metadata":{"labels":{"remediated":"true"}}}`

	dyn := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), pod)
	dyn.PrependReactor("patch", "pods", func(action clienttesting.Action) (bool, runtime.Object, error) {
		patchAction, ok := action.(clienttesting.PatchActionImpl)
		require.True(t, ok)
		require.Equal(t, types.StrategicMergePatchType, patchAction.GetPatchType())
		require.Equal(t, "nginx-pod", patchAction.GetName())
		require.Equal(t, "default", patchAction.GetNamespace())
		require.Equal(t, []string{metav1.DryRunAll}, patchAction.GetPatchOptions().DryRun)
		require.JSONEq(t, patchJSON, string(patchAction.GetPatch()))
		patched := pod.DeepCopy()
		_ = unstructured.SetNestedField(patched.Object, "true", "metadata", "labels", "remediated")
		return true, patched, nil
	})
	ksServer := newTestMCPServerWithK8s(&k8sinterface.KubernetesApi{DynamicClient: dyn})

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "dry_run_remediation", map[string]any{
		"resource_kind": "pods",
		"resource_name": "nginx-pod",
		"namespace":     "default",
		"patch_json":    patchJSON,
	}))
	require.False(t, result.IsError)

	var output map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &output))
	require.Equal(t, "Pod", output["kind"])
	labels, ok := output["metadata"].(map[string]any)["labels"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "true", labels["remediated"])
}
