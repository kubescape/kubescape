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
)

func toolResultText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	require.NotNil(t, result)
	require.Len(t, result.Content, 1)
	content, ok := result.Content[0].(mcp.TextContent)
	require.True(t, ok)
	return content.Text
}

func TestCallToolValidation(t *testing.T) {
	ksServer := &KubescapeMcpserver{}
	tests := []struct {
		name      string
		tool      string
		arguments map[string]any
		wantError string
	}{
		{name: "unknown tool", tool: "missing", arguments: map[string]any{}, wantError: "unknown tool"},
		{name: "vulnerability namespace type", tool: "list_vulnerability_manifests", arguments: map[string]any{"namespace": 42}, wantError: "namespace must be a string"},
		{name: "CVE list requires manifest", tool: "list_vulnerabilities_in_manifest", arguments: map[string]any{}, wantError: "manifest_name is required"},
		{name: "CVE list manifest type", tool: "list_vulnerabilities_in_manifest", arguments: map[string]any{"manifest_name": 42}, wantError: "manifest_name must be a string"},
		{name: "CVE match requires ID", tool: "list_vulnerability_matches_for_cve", arguments: map[string]any{"manifest_name": "manifest"}, wantError: "cve_id is required"},
		{name: "CVE match ID type", tool: "list_vulnerability_matches_for_cve", arguments: map[string]any{"manifest_name": "manifest", "cve_id": 42}, wantError: "cve_id must be a string"},
		{name: "configuration namespace type", tool: "list_configuration_security_scan_manifests", arguments: map[string]any{"namespace": true}, wantError: "namespace must be a string"},
		{name: "configuration get requires name", tool: "get_configuration_security_scan_manifest", arguments: map[string]any{}, wantError: "manifest_name is required"},
		{name: "profile namespace type", tool: "list_container_profiles", arguments: map[string]any{"namespace": true}, wantError: "namespace must be a string"},
		{name: "profile get requires name", tool: "get_container_profile", arguments: map[string]any{}, wantError: "profile_name is required"},
		{name: "profile name type", tool: "get_container_profile", arguments: map[string]any{"profile_name": 42}, wantError: "profile_name must be a string"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := ksServer.CallTool(context.Background(), test.tool, test.arguments)
			require.ErrorContains(t, err, test.wantError)
			assert.Nil(t, result)
		})
	}
}

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
	containerProfile := &storagev1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "deployment-nginx-nginx", Namespace: "security"},
	}
	client := storagefake.NewClientset(vulnerabilityManifest, configurationScan, containerProfile)
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
			arguments:  map[string]any{"namespace": "security", "manifest_name": "nginx-manifest"},
			assertJSON: func(t *testing.T, value any) { require.Len(t, value.([]any), 2) },
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
			name: "list configuration scans", tool: "list_configuration_security_scan_manifests",
			arguments: map[string]any{"namespace": "security"},
			assertJSON: func(t *testing.T, value any) {
				root := value.(map[string]any)
				items := root["configuration_manifests"].(map[string]any)["manifests"].([]any)
				require.Len(t, items, 1)
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
		name string
		uri  string
		want string
	}{
		{name: "default CVE list", uri: "kubescape://vulnerability-manifests/security/manifest", want: "CVE-1"},
		{name: "explicit CVE list", uri: "kubescape://vulnerability-manifests/security/manifest/cve_list", want: "CVE-2"},
		{name: "CVE details", uri: "kubescape://vulnerability-manifests/security/manifest/cve_details/CVE-2", want: "CVE-2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := mcp.ReadResourceRequest{}
			request.Params.URI = test.uri
			contents, err := ksServer.ReadResource(context.Background(), request)
			require.NoError(t, err)
			require.Len(t, contents, 1)
			text, ok := contents[0].(mcp.TextResourceContents)
			require.True(t, ok)
			assert.Contains(t, text.Text, test.want)
		})
	}
}
