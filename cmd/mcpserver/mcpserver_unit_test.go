package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	storagev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	storagefake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

// toolResultText extracts the text content from a CallToolResult for testing.
func toolResultText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	require.NotNil(t, result)
	require.Len(t, result.Content, 1)
	content, ok := result.Content[0].(mcp.TextContent)
	require.True(t, ok)
	return content.Text
}

// TestCallToolValidation verifies parameter validation and error handling across MCP tools.
func TestCallToolValidation(t *testing.T) {
	ksServer := &KubescapeMcpserver{}

	client := storagefake.NewClientset()
	client.PrependReactor("list", "*", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, nil, fmt.Errorf("simulated list error")
	})
	ksErrorServer := &KubescapeMcpserver{ksClient: client.SpdxV1beta1()}

	tests := []struct {
		name            string
		server          *KubescapeMcpserver
		tool            string
		arguments       map[string]any
		wantError       string
		expectToolError bool
	}{
		{name: "unknown tool", server: ksServer, tool: "missing", arguments: map[string]any{}, wantError: "unknown tool", expectToolError: false},
		{name: "vulnerability namespace type", server: ksServer, tool: "list_vulnerability_manifests", arguments: map[string]any{"namespace": 42}, wantError: "namespace argument must be a string", expectToolError: true},
		{name: "CVE list requires manifest", server: ksServer, tool: "list_vulnerabilities_in_manifest", arguments: map[string]any{}, wantError: "manifest_name argument is required", expectToolError: true},
		{name: "CVE list manifest type", server: ksServer, tool: "list_vulnerabilities_in_manifest", arguments: map[string]any{"manifest_name": 42}, wantError: "manifest_name argument must be a string", expectToolError: true},
		{name: "CVE match requires ID", server: ksServer, tool: "list_vulnerability_matches_for_cve", arguments: map[string]any{"manifest_name": "manifest"}, wantError: "cve_id argument is required", expectToolError: true},
		{name: "CVE match ID type", server: ksServer, tool: "list_vulnerability_matches_for_cve", arguments: map[string]any{"manifest_name": "manifest", "cve_id": 42}, wantError: "cve_id argument must be a string", expectToolError: true},
		{name: "configuration namespace type", server: ksServer, tool: "list_configuration_security_scan_manifests", arguments: map[string]any{"namespace": true}, wantError: "namespace argument must be a string", expectToolError: true},
		{name: "configuration continue type", server: ksServer, tool: "list_configuration_security_scan_manifests", arguments: map[string]any{"continue": true}, wantError: "continue argument must be a string", expectToolError: true},
		{name: "configuration get requires name", server: ksServer, tool: "get_configuration_security_scan_manifest", arguments: map[string]any{}, wantError: "manifest_name argument is required", expectToolError: true},
		{name: "profile namespace type", server: ksServer, tool: "list_container_profiles", arguments: map[string]any{"namespace": true}, wantError: "namespace argument must be a string", expectToolError: true},
		{name: "profile continue type", server: ksServer, tool: "list_container_profiles", arguments: map[string]any{"continue": true}, wantError: "continue argument must be a string", expectToolError: true},
		{name: "profile get requires name", server: ksServer, tool: "get_container_profile", arguments: map[string]any{}, wantError: "profile_name argument is required", expectToolError: true},
		{name: "profile name type", server: ksServer, tool: "get_container_profile", arguments: map[string]any{"profile_name": 42}, wantError: "profile_name argument must be a string", expectToolError: true},

		{name: "vulnerability list kubernetes error", server: ksErrorServer, tool: "list_vulnerability_manifests", arguments: map[string]any{}, wantError: "simulated list error", expectToolError: false},
		{name: "configuration list kubernetes error", server: ksErrorServer, tool: "list_configuration_security_scan_manifests", arguments: map[string]any{}, wantError: "simulated list error", expectToolError: false},
		{name: "profile list kubernetes error", server: ksErrorServer, tool: "list_container_profiles", arguments: map[string]any{}, wantError: "simulated list error", expectToolError: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := test.server.CallTool(context.Background(), test.tool, test.arguments)
			if test.expectToolError {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.True(t, result.IsError)
				assert.Contains(t, result.Content[0].(mcp.TextContent).Text, test.wantError)
			} else {
				assert.Error(t, err)
				assert.Nil(t, result)
				assert.Contains(t, err.Error(), test.wantError)
			}
		})
	}
}

// TestCallToolWithStorageResources tests MCP tools against simulated storage resources across multiple namespaces.
func TestCallToolWithStorageResources(t *testing.T) {
	vulnerabilityManifest := &storagev1beta1.VulnerabilityManifest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-manifest",
			Namespace: "security",
			Annotations: map[string]string{
				"kubescape.io/image-id": "sha256:1234",
			},
		},
		Spec: storagev1beta1.VulnerabilityManifestSpec{
			Payload: storagev1beta1.GrypeDocument{Matches: []storagev1beta1.Match{
				{Vulnerability: storagev1beta1.Vulnerability{VulnerabilityMetadata: storagev1beta1.VulnerabilityMetadata{ID: "CVE-2026-0001"}}},
				{Vulnerability: storagev1beta1.Vulnerability{VulnerabilityMetadata: storagev1beta1.VulnerabilityMetadata{ID: "CVE-2026-0002"}}},
			}},
		},
	}
	configurationScan := &storagev1beta1.WorkloadConfigurationScan{
		ObjectMeta: metav1.ObjectMeta{Name: "deployment-nginx", Namespace: "security"},
	}
	configurationScanKubescape := &storagev1beta1.WorkloadConfigurationScan{
		ObjectMeta: metav1.ObjectMeta{Name: "deployment-kubescape", Namespace: "kubescape"},
	}
	containerProfile := &storagev1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "deployment-nginx-nginx", Namespace: "security"},
	}
	client := storagefake.NewClientset(vulnerabilityManifest, configurationScan, configurationScanKubescape, containerProfile)
	ksServer := &KubescapeMcpserver{ksClient: client.SpdxV1beta1()}

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
				root := value.(map[string]any)
				manifests := root["vulnerability_manifests"].(map[string]any)["manifests"].([]any)
				require.Len(t, manifests, 1)
				assert.Equal(t, "nginx-manifest", manifests[0].(map[string]any)["manifest_name"])
			},
		},
		{
			name: "list vulnerabilities", tool: "list_vulnerabilities_in_manifest",
			arguments: map[string]any{"namespace": "security", "manifest_name": "nginx-manifest"},
			assertJSON: func(t *testing.T, value any) {
				require.Len(t, value.(map[string]any)["vulnerabilities"].([]any), 2)
			},
		},
		{
			name: "filter vulnerability matches", tool: "list_vulnerability_matches_for_cve",
			arguments: map[string]any{"namespace": "security", "manifest_name": "nginx-manifest", "cve_id": "CVE-2026-0002"},
			assertJSON: func(t *testing.T, value any) {
				matches := value.([]any)
				require.Len(t, matches, 1)
				assert.Equal(t, "CVE-2026-0002", matches[0].(map[string]any)["vulnerability"].(map[string]any)["id"])
			},
		},
		{
			name: "list configuration scans in specific namespace", tool: "list_configuration_security_scan_manifests",
			arguments: map[string]any{"namespace": "security"},
			assertJSON: func(t *testing.T, value any) {
				root := value.(map[string]any)
				items := root["configuration_manifests"].(map[string]any)["manifests"].([]any)
				require.Len(t, items, 1)
				assert.Equal(t, "deployment-nginx", items[0].(map[string]any)["manifest_name"])
				assert.Equal(t, "security", items[0].(map[string]any)["namespace"])
			},
		},
		{
			name: "list configuration scans default namespace when omitted", tool: "list_configuration_security_scan_manifests",
			arguments: map[string]any{},
			assertJSON: func(t *testing.T, value any) {
				root := value.(map[string]any)
				items := root["configuration_manifests"].(map[string]any)["manifests"].([]any)
				require.Len(t, items, 1)
				assert.Equal(t, "deployment-kubescape", items[0].(map[string]any)["manifest_name"])
				assert.Equal(t, "kubescape", items[0].(map[string]any)["namespace"])
			},
		},
		{
			name: "list configuration scans default namespace when null", tool: "list_configuration_security_scan_manifests",
			arguments: map[string]any{"namespace": nil},
			assertJSON: func(t *testing.T, value any) {
				root := value.(map[string]any)
				items := root["configuration_manifests"].(map[string]any)["manifests"].([]any)
				require.Len(t, items, 1)
				assert.Equal(t, "deployment-kubescape", items[0].(map[string]any)["manifest_name"])
				assert.Equal(t, "kubescape", items[0].(map[string]any)["namespace"])
			},
		},
		{
			name: "list configuration scans all namespaces when empty", tool: "list_configuration_security_scan_manifests",
			arguments: map[string]any{"namespace": ""},
			assertJSON: func(t *testing.T, value any) {
				root := value.(map[string]any)
				items := root["configuration_manifests"].(map[string]any)["manifests"].([]any)
				require.Len(t, items, 2)
			},
		},
		{
			name: "get configuration scan", tool: "get_configuration_security_scan_manifest",
			arguments: map[string]any{"namespace": "security", "manifest_name": "deployment-nginx"},
			assertJSON: func(t *testing.T, value any) {
				assert.Equal(t, "deployment-nginx", value.(map[string]any)["metadata"].(map[string]any)["name"])
			},
		},
		{
			name: "list container profiles", tool: "list_container_profiles",
			arguments: map[string]any{"namespace": "security"},
			assertJSON: func(t *testing.T, value any) {
				root := value.(map[string]any)
				items := root["container_profiles"].(map[string]any)["profiles"].([]any)
				require.Len(t, items, 1)
			},
		},
		{
			name: "get container profile", tool: "get_container_profile",
			arguments: map[string]any{"namespace": "security", "profile_name": "deployment-nginx-nginx"},
			assertJSON: func(t *testing.T, value any) {
				assert.Equal(t, "deployment-nginx-nginx", value.(map[string]any)["metadata"].(map[string]any)["name"])
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := ksServer.CallTool(context.Background(), test.tool, test.arguments)
			require.NoError(t, err)
			var value any
			require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &value))
			test.assertJSON(t, value)
		})
	}
}

func TestMCPToolAndResourceRegistration(t *testing.T) {
	ksServer := &KubescapeMcpserver{s: server.NewMCPServer("kubescape-test", "test")}
	require.NotPanics(t, func() {
		createVulnerabilityToolsAndResources(ksServer)
		createConfigurationsToolsAndResources(ksServer)
		createRuntimeToolsAndResources(ksServer)
		createRBACScanningTools(ksServer)
		createNetworkScanningTools(ksServer)
		createFrameworkScanningTools(ksServer)
		createWorkloadScanningTools(ksServer)
	})
	assert.NotNil(t, GetMCPServerCmd())
}

func TestReadResourceWithFakeClient(t *testing.T) {
	manifest := &storagev1beta1.VulnerabilityManifest{
		ObjectMeta: metav1.ObjectMeta{Name: "manifest", Namespace: "security"},
		Spec: storagev1beta1.VulnerabilityManifestSpec{Payload: storagev1beta1.GrypeDocument{Matches: []storagev1beta1.Match{
			{Vulnerability: storagev1beta1.Vulnerability{VulnerabilityMetadata: storagev1beta1.VulnerabilityMetadata{ID: "CVE-1"}}},
			{Vulnerability: storagev1beta1.Vulnerability{VulnerabilityMetadata: storagev1beta1.VulnerabilityMetadata{ID: "CVE-2"}}},
		}}},
	}
	client := storagefake.NewClientset(manifest)
	ksServer := &KubescapeMcpserver{ksClient: client.SpdxV1beta1()}

	for _, test := range []struct {
		name    string
		uri     string
		wantIDs []string
		details bool
	}{
		{name: "default CVE list", uri: "kubescape://vulnerability-manifests/security/manifest", wantIDs: []string{"CVE-1", "CVE-2"}},
		{name: "explicit CVE list", uri: "kubescape://vulnerability-manifests/security/manifest/cve_list", wantIDs: []string{"CVE-1", "CVE-2"}},
		{name: "CVE details", uri: "kubescape://vulnerability-manifests/security/manifest/cve_details/CVE-2", wantIDs: []string{"CVE-2"}, details: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := mcp.ReadResourceRequest{}
			request.Params.URI = test.uri
			contents, err := ksServer.ReadResource(context.Background(), request)
			require.NoError(t, err)
			require.Len(t, contents, 1)
			text, ok := contents[0].(mcp.TextResourceContents)
			require.True(t, ok)

			var resources []map[string]any
			require.NoError(t, json.Unmarshal([]byte(text.Text), &resources))
			require.Len(t, resources, len(test.wantIDs))
			ids := make([]string, 0, len(resources))
			for _, resource := range resources {
				if test.details {
					vulnerability := resource["vulnerability"].(map[string]any)
					ids = append(ids, vulnerability["id"].(string))
					continue
				}
				ids = append(ids, resource["id"].(string))
			}
			require.ElementsMatch(t, test.wantIDs, ids)
		})
	}
}

func TestGetConfigurationDrift_MarshalErrorIsToolError(t *testing.T) {
	orig := jsonMarshal
	t.Cleanup(func() { jsonMarshal = orig })
	jsonMarshal = func(any) ([]byte, error) {
		return nil, fmt.Errorf("marshal boom")
	}

	profile := &storagev1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "nginx-profile", Namespace: "default"},
	}
	ksClient := storagefake.NewClientset(profile)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "nginx", Namespace: "default"},
	}
	ksServer := &KubescapeMcpserver{
		ksClient: ksClient.SpdxV1beta1(),
		k8sClient: &k8sinterface.KubernetesApi{
			KubernetesClient: fake.NewClientset(pod),
		},
	}

	result, err := ksServer.CallTool(context.Background(), "get_configuration_drift", map[string]any{
		"profile_name":  "nginx-profile",
		"workload_name": "nginx",
		"workload_kind": "pod",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.IsError)
	text := toolResultText(t, result)
	assert.Contains(t, text, "failed to marshal workload manifest")
	assert.Contains(t, text, "marshal boom")
}

func TestGetConfigurationDrift_SupportsAllWorkloadKinds(t *testing.T) {
	profile := &storagev1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "test-profile", Namespace: "default"},
	}
	ksClient := storagefake.NewClientset(profile)

	// The fake k8s client returns "not found" for all workloads, but that's fine:
	// we only need to verify the tool doesn't reject the kind as "unsupported".
	ksServer := &KubescapeMcpserver{
		ksClient: ksClient.SpdxV1beta1(),
		k8sClient: &k8sinterface.KubernetesApi{
			KubernetesClient: fake.NewClientset(),
		},
	}

	for _, kind := range []string{"pod", "deployment", "daemonset", "statefulset", "replicaset", "job", "cronjob"} {
		t.Run(kind, func(t *testing.T) {
			result, err := ksServer.CallTool(context.Background(), "get_configuration_drift", map[string]any{
				"profile_name":  "test-profile",
				"workload_name": "test-workload",
				"workload_kind": kind,
			})
			require.NoError(t, err)
			require.NotNil(t, result)
			text := toolResultText(t, result)
			// The error should be "not found" (workload doesn't exist in the fake client),
			// NOT "unsupported workload kind" which would mean the kind was rejected.
			assert.NotContains(t, text, "unsupported workload kind")
		})
	}
}

func TestGetConfigurationDrift_WhitespaceArgumentsRejected(t *testing.T) {
	ksServer := &KubescapeMcpserver{}
	requiredArgs := []string{"profile_name", "workload_name", "workload_kind"}
	for _, arg := range requiredArgs {
		t.Run(arg, func(t *testing.T) {
			args := map[string]any{
				"profile_name":  "test-profile",
				"workload_name": "test-workload",
				"workload_kind": "pod",
			}
			args[arg] = "   "
			result, err := ksServer.CallTool(context.Background(), "get_configuration_drift", args)
			require.NoError(t, err)
			require.NotNil(t, result)
			require.True(t, result.IsError)
			var toolErr ToolError
			require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
			assert.Equal(t, ErrCodeInvalidArgument, toolErr.Code)
			assert.Equal(t, arg, toolErr.Details["argument"])
		})
	}
}
