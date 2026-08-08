package mcpserver

import (
	"context"
	"encoding/json"
	"testing"

	storagev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	storagefake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestRegisteredStorageToolsRejectMalformedArguments(t *testing.T) {
	tools := []string{
		"list_vulnerability_manifests",
		"list_vulnerabilities_in_manifest",
		"list_vulnerability_matches_for_cve",
		"list_configuration_security_scan_manifests",
		"get_configuration_security_scan_manifest",
		"scan_container_image",
	}
	malformed := []struct {
		name      string
		arguments any
	}{
		{name: "string", arguments: "namespace=default"},
		{name: "array", arguments: []any{"default"}},
		{name: "number", arguments: float64(42)},
		{name: "boolean", arguments: true},
	}
	ksServer := newRegisteredStorageToolTestServer()

	for _, tool := range tools {
		t.Run(tool, func(t *testing.T) {
			for _, tt := range malformed {
				t.Run(tt.name, func(t *testing.T) {
					result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, tool, tt.arguments))
					assert.True(t, result.IsError)
					assert.Equal(t, "arguments must be a JSON object", toolResultText(t, result))
				})
			}
		})
	}
}

func TestRegisteredStorageToolsAcceptNullAsNoArguments(t *testing.T) {
	ksServer := newRegisteredStorageToolTestServer()
	for _, tool := range []string{
		"list_vulnerability_manifests",
		"list_configuration_security_scan_manifests",
	} {
		t.Run(tool, func(t *testing.T) {
			result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, tool, nil))
			assert.False(t, result.IsError)
		})
	}
}

func TestRegisteredStorageToolsDispatchToTheirDeclaredNames(t *testing.T) {
	vulnerabilityManifest := &storagev1beta1.VulnerabilityManifest{
		ObjectMeta: metav1.ObjectMeta{Name: "nginx", Namespace: "security"},
		Spec: storagev1beta1.VulnerabilityManifestSpec{
			Payload: storagev1beta1.GrypeDocument{Matches: []storagev1beta1.Match{
				{Vulnerability: storagev1beta1.Vulnerability{
					VulnerabilityMetadata: storagev1beta1.VulnerabilityMetadata{ID: "CVE-2026-1000"},
				}},
			}},
		},
	}
	configurationManifest := &storagev1beta1.WorkloadConfigurationScan{
		ObjectMeta: metav1.ObjectMeta{Name: "deployment-nginx", Namespace: "security"},
	}
	ksServer := newRegisteredStorageToolTestServer(vulnerabilityManifest, configurationManifest)

	tests := []struct {
		name       string
		tool       string
		arguments  map[string]any
		assertJSON func(*testing.T, any)
	}{
		{
			name: "list vulnerability manifests", tool: "list_vulnerability_manifests",
			arguments: map[string]any{"namespace": "security", "level": "both"},
			assertJSON: func(t *testing.T, value any) {
				manifests := value.(map[string]any)["vulnerability_manifests"].(map[string]any)["manifests"].([]any)
				require.Len(t, manifests, 1)
				assert.Equal(t, "nginx", manifests[0].(map[string]any)["manifest_name"])
			},
		},
		{
			name: "list vulnerabilities", tool: "list_vulnerabilities_in_manifest",
			arguments: map[string]any{"namespace": "security", "manifest_name": "nginx"},
			assertJSON: func(t *testing.T, value any) {
				vulnerabilities := value.([]any)
				require.Len(t, vulnerabilities, 1)
				assert.Equal(t, "CVE-2026-1000", vulnerabilities[0].(map[string]any)["id"])
			},
		},
		{
			name: "list CVE matches", tool: "list_vulnerability_matches_for_cve",
			arguments: map[string]any{"namespace": "security", "manifest_name": "nginx", "cve_id": "CVE-2026-1000"},
			assertJSON: func(t *testing.T, value any) {
				matches := value.([]any)
				require.Len(t, matches, 1)
				vulnerability := matches[0].(map[string]any)["vulnerability"].(map[string]any)
				assert.Equal(t, "CVE-2026-1000", vulnerability["id"])
			},
		},
		{
			name: "list configuration manifests", tool: "list_configuration_security_scan_manifests",
			arguments: map[string]any{"namespace": "security"},
			assertJSON: func(t *testing.T, value any) {
				manifests := value.(map[string]any)["configuration_manifests"].(map[string]any)["manifests"].([]any)
				require.Len(t, manifests, 1)
				assert.Equal(t, "deployment-nginx", manifests[0].(map[string]any)["manifest_name"])
			},
		},
		{
			name: "get configuration manifest", tool: "get_configuration_security_scan_manifest",
			arguments: map[string]any{"namespace": "security", "manifest_name": "deployment-nginx"},
			assertJSON: func(t *testing.T, value any) {
				metadata := value.(map[string]any)["metadata"].(map[string]any)
				assert.Equal(t, "deployment-nginx", metadata["name"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, tt.tool, tt.arguments))
			require.False(t, result.IsError)
			var value any
			require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &value))
			tt.assertJSON(t, value)
		})
	}
}

func dispatchRegisteredTool(t *testing.T, ksServer *KubescapeMcpserver, tool string, arguments any) mcp.JSONRPCMessage {
	t.Helper()
	message, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      tool,
			"arguments": arguments,
		},
	})
	require.NoError(t, err)
	return ksServer.s.HandleMessage(context.Background(), message)
}

func registeredToolResult(t *testing.T, message mcp.JSONRPCMessage) *mcp.CallToolResult {
	t.Helper()
	response, ok := message.(mcp.JSONRPCResponse)
	require.True(t, ok, "tool call returned a protocol error: %#v", message)
	result, ok := response.Result.(mcp.CallToolResult)
	require.True(t, ok)
	return &result
}

func newRegisteredStorageToolTestServer(objects ...runtime.Object) *KubescapeMcpserver {
	client := storagefake.NewClientset(objects...)
	ksServer := &KubescapeMcpserver{
		s: server.NewMCPServer(
			"kubescape-test",
			"test",
			server.WithToolCapabilities(false),
			server.WithRecovery(),
		),
		ksClient: client.SpdxV1beta1(),
	}
	createVulnerabilityToolsAndResources(ksServer)
	createConfigurationsToolsAndResources(ksServer)
	createImageScanningTools(ksServer)
	return ksServer
}
