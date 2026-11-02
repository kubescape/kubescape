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

// TestScanResourceSlice_PropagatesLabelsAnnotationsAndCreationTimestamp verifies
// that simplified items preserve labels, annotations, creationTimestamp, and
// ownerReferences, while stripping noisy annotations like last-applied-configuration,
// so downstream security analysis tools have the necessary metadata.
func TestScanResourceSlice_PropagatesLabelsAnnotationsAndCreationTimestamp(t *testing.T) {
	listKinds := map[schema.GroupVersionResource]string{
		{Group: "", Version: "v1", Resource: "pods"}:            "PodList",
		{Group: "apps", Version: "v1", Resource: "deployments"}: "DeploymentList",
	}

	podWithMeta := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]any{
				"name":      "security-pod",
				"namespace": "prod",
				"labels":    map[string]any{"app": "web", "tier": "frontend"},
				"annotations": map[string]any{
					"kubescape.io/skip-controls":                       "C-0001",
					"kubectl.kubernetes.io/last-applied-configuration": `{"apiVersion":"v1","kind":"Pod"}`,
				},
				"creationTimestamp": "2026-01-01T00:00:00Z",
				"ownerReferences": []any{
					map[string]any{
						"apiVersion": "apps/v1",
						"kind":       "ReplicaSet",
						"name":       "web-rs",
						"uid":        "1234-5678",
					},
				},
				"managedFields": []any{"noisy"},
			},
			"spec": map[string]any{
				"containers": []any{
					map[string]any{"name": "nginx", "image": "nginx:1.25"},
				},
			},
			"status": map[string]any{
				"phase": "Running",
			},
		},
	}

	podWithoutMeta := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]any{
				"name":      "plain-pod",
				"namespace": "prod",
				"annotations": map[string]any{
					"kubectl.kubernetes.io/last-applied-configuration": `{"apiVersion":"v1","kind":"Pod"}`,
				},
			},
			"spec": map[string]any{
				"containers": []any{
					map[string]any{"name": "busybox", "image": "busybox:latest"},
				},
			},
		},
	}

	deployment := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]any{
				"name":              "web-deploy",
				"namespace":         "prod",
				"labels":            map[string]any{"app": "web"},
				"creationTimestamp": "2026-01-01T00:00:00Z",
			},
			"spec": map[string]any{
				"replicas": float64(3),
				"template": map[string]any{
					"metadata": map[string]any{
						"labels": map[string]any{"app": "web"},
					},
				},
			},
			"status": map[string]any{
				"readyReplicas": float64(3),
			},
		},
	}

	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, podWithMeta, podWithoutMeta, deployment)
	ksServer := newTestMCPServerWithK8s(&k8sinterface.KubernetesApi{DynamicClient: dyn})

	// 1. Pods without include_status (default: false)
	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "scan_resource_slice", map[string]any{
		"resource_kind": "pods",
		"namespace":     "prod",
	}))
	require.False(t, result.IsError)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
	require.Equal(t, float64(2), parsed["count"])

	resources, ok := parsed["resources"].([]any)
	require.True(t, ok)
	require.Len(t, resources, 2)

	var secPod, plainPod map[string]any
	for _, r := range resources {
		rm, isMap := r.(map[string]any)
		require.True(t, isMap)
		meta, isMeta := rm["metadata"].(map[string]any)
		require.True(t, isMeta)
		switch meta["name"] {
		case "security-pod":
			secPod = rm
		case "plain-pod":
			plainPod = rm
		}
	}
	require.NotNil(t, secPod, "security-pod must be found in resources")
	require.NotNil(t, plainPod, "plain-pod must be found in resources")

	// First pod has labels, real annotation, creationTimestamp, ownerReferences;
	// last-applied-configuration, status, and managedFields stripped
	require.Equal(t, "v1", secPod["apiVersion"])
	require.Equal(t, "Pod", secPod["kind"])
	require.NotNil(t, secPod["spec"])
	require.Nil(t, secPod["status"], "status must be excluded when include_status is omitted")

	secMeta := secPod["metadata"].(map[string]any)
	require.Equal(t, "security-pod", secMeta["name"])
	require.Equal(t, "prod", secMeta["namespace"])
	require.Equal(t, map[string]any{"app": "web", "tier": "frontend"}, secMeta["labels"])
	require.Equal(t, map[string]any{"kubescape.io/skip-controls": "C-0001"}, secMeta["annotations"])
	require.Equal(t, "2026-01-01T00:00:00Z", secMeta["creationTimestamp"])
	require.NotNil(t, secMeta["ownerReferences"])
	ownerRefs, ok := secMeta["ownerReferences"].([]any)
	require.True(t, ok)
	require.Len(t, ownerRefs, 1)
	ownerRef0 := ownerRefs[0].(map[string]any)
	require.Equal(t, "web-rs", ownerRef0["name"])
	require.Equal(t, "ReplicaSet", ownerRef0["kind"])
	require.Nil(t, secMeta["managedFields"], "managedFields should be stripped")

	// Plain pod had only last-applied-configuration; ensure annotations, labels, timestamp, ownerRefs are omitted
	plainMeta := plainPod["metadata"].(map[string]any)
	require.Equal(t, "plain-pod", plainMeta["name"])
	require.Equal(t, "prod", plainMeta["namespace"])
	_, hasLabels := plainMeta["labels"]
	require.False(t, hasLabels, "labels should be omitted when absent")
	_, hasAnnotations := plainMeta["annotations"]
	require.False(t, hasAnnotations, "annotations should be omitted when only last-applied-configuration existed")
	_, hasTimestamp := plainMeta["creationTimestamp"]
	require.False(t, hasTimestamp, "creationTimestamp should be omitted when absent")
	_, hasOwnerRefs := plainMeta["ownerReferences"]
	require.False(t, hasOwnerRefs, "ownerReferences should be omitted when absent")

	// 2. include_status: null behaves as false
	resultNullStatus := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "scan_resource_slice", map[string]any{
		"resource_kind":  "pods",
		"namespace":      "prod",
		"include_status": nil,
	}))
	require.False(t, resultNullStatus.IsError)
	var parsedNullStatus map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, resultNullStatus)), &parsedNullStatus))
	for _, r := range parsedNullStatus["resources"].([]any) {
		require.Nil(t, r.(map[string]any)["status"], "status must be omitted when include_status is null")
	}

	// 3. With include_status: true
	resultStatus := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "scan_resource_slice", map[string]any{
		"resource_kind":  "pods",
		"namespace":      "prod",
		"include_status": true,
	}))
	require.False(t, resultStatus.IsError)

	var parsedStatus map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, resultStatus)), &parsedStatus))
	resourcesStatus := parsedStatus["resources"].([]any)
	var secPodWithStatus map[string]any
	for _, r := range resourcesStatus {
		rm := r.(map[string]any)
		meta := rm["metadata"].(map[string]any)
		if meta["name"] == "security-pod" {
			secPodWithStatus = rm
		}
	}
	require.NotNil(t, secPodWithStatus)
	require.Equal(t, map[string]any{"phase": "Running"}, secPodWithStatus["status"])

	// 4. Test controller kind (Deployment)
	resultDeploy := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "scan_resource_slice", map[string]any{
		"resource_kind":  "deployments",
		"namespace":      "prod",
		"include_status": true,
	}))
	require.False(t, resultDeploy.IsError)

	var parsedDeploy map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, resultDeploy)), &parsedDeploy))
	require.Equal(t, float64(1), parsedDeploy["count"])
	deployRes := parsedDeploy["resources"].([]any)[0].(map[string]any)
	require.Equal(t, "apps/v1", deployRes["apiVersion"])
	require.Equal(t, "Deployment", deployRes["kind"])
	deployMeta := deployRes["metadata"].(map[string]any)
	require.Equal(t, "web-deploy", deployMeta["name"])
	require.Equal(t, map[string]any{"app": "web"}, deployMeta["labels"])
	require.Equal(t, "2026-01-01T00:00:00Z", deployMeta["creationTimestamp"])
	require.Equal(t, map[string]any{"readyReplicas": float64(3)}, deployRes["status"])
}

// TestScanResourceSlice_UnsupportedKindReturnsError guards against a silent
// fallback to core/v1 for resource kinds the tool does not explicitly map
// (e.g. "services"). Falling back would send a request to the wrong API group and
// surface the cluster's "resource not found" rejection as an opaque list
// failure, indistinguishable from a connectivity problem.
func TestScanResourceSlice_UnsupportedKindReturnsError(t *testing.T) {
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{})
	ksServer := newTestMCPServerWithK8s(&k8sinterface.KubernetesApi{DynamicClient: dyn})

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "scan_resource_slice", map[string]any{
		"resource_kind": "services",
	}))
	require.True(t, result.IsError)
	var toolErr ToolError
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
	require.Equal(t, ErrCodeUnsupportedResource, toolErr.Code)
	require.Contains(t, toolErr.Message, `unsupported resource kind "services"`)
	require.Contains(t, toolErr.Message, "pods")
	require.Contains(t, toolErr.Message, "deployments")
	require.Contains(t, toolErr.Message, "daemonsets")
	require.Contains(t, toolErr.Message, "statefulsets")
	require.Contains(t, toolErr.Message, "replicasets")
	require.Contains(t, toolErr.Message, "jobs")
	require.Contains(t, toolErr.Message, "cronjobs")
	require.Equal(t, "services", toolErr.Details["kind"])
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
		"resource_kind": "services",
	}))
	require.True(t, result.IsError)
	var toolErr ToolError
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
	require.Equal(t, ErrCodeUnsupportedResource, toolErr.Code)
	require.Contains(t, toolErr.Message, `unsupported resource kind "services"`)
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
		{
			name:         "invalid include_status type",
			arguments:    map[string]any{"resource_kind": "pods", "include_status": "not-a-boolean"},
			expectedCode: ErrCodeInvalidArgument,
			expectedArg:  "include_status",
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
		{
			name: "invalid patch_type type",
			arguments: map[string]any{
				"resource_kind": "pods",
				"resource_name": "app",
				"patch_json":    validPatch,
				"patch_type":    1234,
			},
			expectedCode: ErrCodeInvalidArgument,
			expectedArg:  "patch_type",
		},
		{
			name: "unsupported patch_type",
			arguments: map[string]any{
				"resource_kind": "pods",
				"resource_name": "app",
				"patch_json":    validPatch,
				"patch_type":    "unsupported-patch-type",
			},
			expectedCode: ErrCodeInvalidArgument,
			expectedArg:  "patch_type",
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

func TestScanResourceSlice_MarshalError(t *testing.T) {
	origMarshal := jsonMarshal
	t.Cleanup(func() { jsonMarshal = origMarshal })
	jsonMarshal = func(any) ([]byte, error) {
		return nil, errors.New("simulated marshal error")
	}

	listKinds := map[schema.GroupVersionResource]string{
		podGVR: "PodList",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds)
	ksServer := newTestMCPServerWithK8s(&k8sinterface.KubernetesApi{DynamicClient: dyn})

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "scan_resource_slice", map[string]any{
		"resource_kind": "pods",
	}))
	require.True(t, result.IsError)

	var toolErr ToolError
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
	require.Equal(t, ErrCodeMarshalError, toolErr.Code)
	require.Contains(t, toolErr.Message, "failed to marshal result: simulated marshal error")
}

func TestDryRunRemediation_MarshalError(t *testing.T) {
	origMarshal := jsonMarshal
	t.Cleanup(func() { jsonMarshal = origMarshal })
	jsonMarshal = func(any) ([]byte, error) {
		return nil, errors.New("simulated marshal error")
	}

	pod := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]any{
				"name":      "nginx-pod",
				"namespace": "default",
			},
		},
	}
	patchJSON := `{"metadata":{"labels":{"remediated":"true"}}}`
	dyn := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), pod)
	dyn.PrependReactor("patch", "pods", func(action clienttesting.Action) (bool, runtime.Object, error) {
		return true, pod.DeepCopy(), nil
	})
	ksServer := newTestMCPServerWithK8s(&k8sinterface.KubernetesApi{DynamicClient: dyn})

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "dry_run_remediation", map[string]any{
		"resource_kind": "pods",
		"resource_name": "nginx-pod",
		"namespace":     "default",
		"patch_json":    patchJSON,
	}))
	require.True(t, result.IsError)

	var toolErr ToolError
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
	require.Equal(t, ErrCodeMarshalError, toolErr.Code)
	require.Contains(t, toolErr.Message, "failed to marshal result: simulated marshal error")
}

func TestDryRunRemediation_PatchTypes(t *testing.T) {
	pod := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]any{
				"name":      "nginx-pod",
				"namespace": "default",
			},
		},
	}
	defaultPatchJSON := `{"metadata":{"labels":{"remediated":"true"}}}`
	jsonPatchJSON := `[{"op":"add","path":"/metadata/labels/remediated","value":"true"}]`

	testCases := []struct {
		name              string
		patchTypeArg      any
		patchPayload      string
		expectedPatchType types.PatchType
	}{
		{
			name:              "default when patch_type is omitted",
			patchTypeArg:      nil,
			patchPayload:      defaultPatchJSON,
			expectedPatchType: types.StrategicMergePatchType,
		},
		{
			name:              "explicit strategic-merge-patch",
			patchTypeArg:      "strategic-merge-patch",
			patchPayload:      defaultPatchJSON,
			expectedPatchType: types.StrategicMergePatchType,
		},
		{
			name:              "explicit merge-patch",
			patchTypeArg:      "merge-patch",
			patchPayload:      defaultPatchJSON,
			expectedPatchType: types.MergePatchType,
		},
		{
			name:              "explicit json-patch",
			patchTypeArg:      "json-patch",
			patchPayload:      jsonPatchJSON,
			expectedPatchType: types.JSONPatchType,
		},
		{
			name:              "case-insensitive patch type",
			patchTypeArg:      "Merge-Patch",
			patchPayload:      defaultPatchJSON,
			expectedPatchType: types.MergePatchType,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dyn := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), pod)
			var capturedPatchType types.PatchType
			var capturedPatchBytes []byte
			dyn.PrependReactor("patch", "pods", func(action clienttesting.Action) (bool, runtime.Object, error) {
				patchAction, ok := action.(clienttesting.PatchActionImpl)
				require.True(t, ok)
				capturedPatchType = patchAction.GetPatchType()
				capturedPatchBytes = patchAction.GetPatch()
				patched := pod.DeepCopy()
				_ = unstructured.SetNestedField(patched.Object, "true", "metadata", "labels", "remediated")
				return true, patched, nil
			})
			ksServer := newTestMCPServerWithK8s(&k8sinterface.KubernetesApi{DynamicClient: dyn})

			args := map[string]any{
				"resource_kind": "pods",
				"resource_name": "nginx-pod",
				"namespace":     "default",
				"patch_json":    tc.patchPayload,
			}
			if tc.patchTypeArg != nil {
				args["patch_type"] = tc.patchTypeArg
			}

			result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "dry_run_remediation", args))
			require.False(t, result.IsError)
			require.Equal(t, tc.expectedPatchType, capturedPatchType)
			require.JSONEq(t, tc.patchPayload, string(capturedPatchBytes))
		})
	}
}

func TestScanResourceSlice_SupportedWorkloadKinds(t *testing.T) {
	listKinds := map[schema.GroupVersionResource]string{
		podGVR:         "PodList",
		deploymentGVR:  "DeploymentList",
		daemonSetGVR:   "DaemonSetList",
		statefulSetGVR: "StatefulSetList",
		replicaSetGVR:  "ReplicaSetList",
		jobGVR:         "JobList",
		cronJobGVR:     "CronJobList",
	}

	testCases := []struct {
		kind string
	}{
		{kind: "pods"},
		{kind: "pod"},
		{kind: "deployments"},
		{kind: "deployment"},
		{kind: "daemonsets"},
		{kind: "daemonset"},
		{kind: "statefulsets"},
		{kind: "statefulset"},
		{kind: "replicasets"},
		{kind: "replicaset"},
		{kind: "jobs"},
		{kind: "job"},
		{kind: "cronjobs"},
		{kind: "cronjob"},
	}

	for _, tc := range testCases {
		t.Run(tc.kind, func(t *testing.T) {
			dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds)
			ksServer := newTestMCPServerWithK8s(&k8sinterface.KubernetesApi{DynamicClient: dyn})

			result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "scan_resource_slice", map[string]any{
				"resource_kind": tc.kind,
			}))
			require.False(t, result.IsError)
			raw := toolResultText(t, result)
			require.JSONEq(t, `{"resources":[],"continue":"","count":0}`, raw)
		})
	}
}

func TestDryRunRemediation_SupportedWorkloadKinds(t *testing.T) {
	testCases := []struct {
		kind         string
		resourceName string
		expectedKind string
		gvrResource  string
	}{
		{kind: "pods", resourceName: "test-pod", expectedKind: "Pod", gvrResource: "pods"},
		{kind: "pod", resourceName: "test-pod", expectedKind: "Pod", gvrResource: "pods"},
		{kind: "deployments", resourceName: "test-deploy", expectedKind: "Deployment", gvrResource: "deployments"},
		{kind: "deployment", resourceName: "test-deploy", expectedKind: "Deployment", gvrResource: "deployments"},
		{kind: "daemonsets", resourceName: "test-daemon", expectedKind: "DaemonSet", gvrResource: "daemonsets"},
		{kind: "daemonset", resourceName: "test-daemon", expectedKind: "DaemonSet", gvrResource: "daemonsets"},
		{kind: "statefulsets", resourceName: "test-stateful", expectedKind: "StatefulSet", gvrResource: "statefulsets"},
		{kind: "statefulset", resourceName: "test-stateful", expectedKind: "StatefulSet", gvrResource: "statefulsets"},
		{kind: "replicasets", resourceName: "test-rs", expectedKind: "ReplicaSet", gvrResource: "replicasets"},
		{kind: "replicaset", resourceName: "test-rs", expectedKind: "ReplicaSet", gvrResource: "replicasets"},
		{kind: "jobs", resourceName: "test-job", expectedKind: "Job", gvrResource: "jobs"},
		{kind: "job", resourceName: "test-job", expectedKind: "Job", gvrResource: "jobs"},
		{kind: "cronjobs", resourceName: "test-cj", expectedKind: "CronJob", gvrResource: "cronjobs"},
		{kind: "cronjob", resourceName: "test-cj", expectedKind: "CronJob", gvrResource: "cronjobs"},
	}

	patchJSON := `{"metadata":{"labels":{"remediated":"true"}}}`

	for _, tc := range testCases {
		t.Run(tc.kind, func(t *testing.T) {
			obj := &unstructured.Unstructured{
				Object: map[string]any{
					"apiVersion": "v1",
					"kind":       tc.expectedKind,
					"metadata": map[string]any{
						"name":      tc.resourceName,
						"namespace": "default",
					},
				},
			}

			dyn := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), obj)
			dyn.PrependReactor("patch", tc.gvrResource, func(action clienttesting.Action) (bool, runtime.Object, error) {
				patchAction, ok := action.(clienttesting.PatchActionImpl)
				require.True(t, ok)
				require.Equal(t, types.StrategicMergePatchType, patchAction.GetPatchType())
				require.Equal(t, tc.resourceName, patchAction.GetName())
				require.Equal(t, "default", patchAction.GetNamespace())
				require.Equal(t, []string{metav1.DryRunAll}, patchAction.GetPatchOptions().DryRun)
				require.JSONEq(t, patchJSON, string(patchAction.GetPatch()))
				patched := obj.DeepCopy()
				_ = unstructured.SetNestedField(patched.Object, "true", "metadata", "labels", "remediated")
				return true, patched, nil
			})

			ksServer := newTestMCPServerWithK8s(&k8sinterface.KubernetesApi{DynamicClient: dyn})

			result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "dry_run_remediation", map[string]any{
				"resource_kind": tc.kind,
				"resource_name": tc.resourceName,
				"namespace":     "default",
				"patch_json":    patchJSON,
			}))
			require.False(t, result.IsError)

			var output map[string]any
			require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &output))
			require.Equal(t, tc.expectedKind, output["kind"])
			labels, ok := output["metadata"].(map[string]any)["labels"].(map[string]any)
			require.True(t, ok)
			require.Equal(t, "true", labels["remediated"])
		})
	}
}
