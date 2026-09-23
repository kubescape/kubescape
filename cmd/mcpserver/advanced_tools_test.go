package mcpserver

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

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

	ksServer := &KubescapeMcpserver{
		s: server.NewMCPServer(
			"kubescape-test",
			"test",
			server.WithToolCapabilities(false),
			server.WithRecovery(),
		),
		k8sClient: &k8sinterface.KubernetesApi{DynamicClient: dyn},
	}
	createAdvancedTools(ksServer)

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

	ksServer := &KubescapeMcpserver{
		s: server.NewMCPServer(
			"kubescape-test",
			"test",
			server.WithToolCapabilities(false),
			server.WithRecovery(),
		),
		k8sClient: &k8sinterface.KubernetesApi{DynamicClient: dyn},
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
	require.Contains(t, toolErr.Message, "pods")
	require.Contains(t, toolErr.Message, "deployments")
	require.Contains(t, toolErr.Message, "daemonsets")
	require.Contains(t, toolErr.Message, "statefulsets")
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
