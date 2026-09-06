package mcpserver

import (
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
	require.Contains(t, toolResultText(t, result), `unsupported resource kind "jobs"`)
}
