package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/anchore/grype/grype/presenter/models"
	storagev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	storagefake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clienttesting "k8s.io/client-go/testing"
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

	client := storagefake.NewClientset()
	client.PrependReactor("list", "*", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, nil, fmt.Errorf("simulated list error")
	})
	ksErrorServer := &KubescapeMcpserver{ksClient: client.SpdxV1beta1()}

	tests := []struct {
		name      string
		server    *KubescapeMcpserver
		tool      string
		arguments map[string]any
		wantError string
	}{
		{name: "unknown tool", server: ksServer, tool: "missing", arguments: map[string]any{}, wantError: "unknown tool"},
		{name: "vulnerability namespace type", server: ksServer, tool: "list_vulnerability_manifests", arguments: map[string]any{"namespace": 42}, wantError: "namespace must be a string"},
		{name: "CVE list requires manifest", server: ksServer, tool: "list_vulnerabilities_in_manifest", arguments: map[string]any{}, wantError: "manifest_name is required"},
		{name: "CVE list manifest type", server: ksServer, tool: "list_vulnerabilities_in_manifest", arguments: map[string]any{"manifest_name": 42}, wantError: "manifest_name must be a string"},
		{name: "CVE match requires ID", server: ksServer, tool: "list_vulnerability_matches_for_cve", arguments: map[string]any{"manifest_name": "manifest"}, wantError: "cve_id is required"},
		{name: "CVE match ID type", server: ksServer, tool: "list_vulnerability_matches_for_cve", arguments: map[string]any{"manifest_name": "manifest", "cve_id": 42}, wantError: "cve_id must be a string"},
		{name: "configuration namespace type", server: ksServer, tool: "list_configuration_security_scan_manifests", arguments: map[string]any{"namespace": true}, wantError: "namespace must be a string"},
		{name: "configuration get requires name", server: ksServer, tool: "get_configuration_security_scan_manifest", arguments: map[string]any{}, wantError: "manifest_name is required"},
		{name: "profile namespace type", server: ksServer, tool: "list_container_profiles", arguments: map[string]any{"namespace": true}, wantError: "namespace must be a string"},
		{name: "profile get requires name", server: ksServer, tool: "get_container_profile", arguments: map[string]any{}, wantError: "profile_name is required"},
		{name: "profile name type", server: ksServer, tool: "get_container_profile", arguments: map[string]any{"profile_name": 42}, wantError: "profile_name must be a string"},

		{name: "vulnerability list kubernetes error", server: ksErrorServer, tool: "list_vulnerability_manifests", arguments: map[string]any{}, wantError: "failed to list vulnerability manifests: simulated list error"},
		{name: "configuration list kubernetes error", server: ksErrorServer, tool: "list_configuration_security_scan_manifests", arguments: map[string]any{}, wantError: "failed to list configuration scans: simulated list error"},
		{name: "profile list kubernetes error", server: ksErrorServer, tool: "list_container_profiles", arguments: map[string]any{}, wantError: "failed to list container profiles: simulated list error"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := test.server.CallTool(context.Background(), test.tool, test.arguments)
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.True(t, result.IsError)
			assert.Contains(t, toolResultText(t, result), test.wantError)
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

func TestScanContainerImageValidation(t *testing.T) {
	ksServer := &KubescapeMcpserver{}
	tests := []struct {
		name      string
		arguments map[string]any
		wantError string
	}{
		{name: "missing image_name", arguments: map[string]any{}, wantError: "image_name argument is required and cannot be empty"},
		{name: "empty image_name", arguments: map[string]any{"image_name": "  "}, wantError: "image_name argument is required and cannot be empty"},
		{name: "invalid image_name type", arguments: map[string]any{"image_name": 123}, wantError: "image_name argument must be a string"},
		{name: "invalid username type", arguments: map[string]any{"image_name": "nginx:alpine", "username": true}, wantError: "username argument must be a string"},
		{name: "invalid password type", arguments: map[string]any{"image_name": "nginx:alpine", "password": 456}, wantError: "password argument must be a string"},
		{name: "invalid include_matches type", arguments: map[string]any{"image_name": "nginx:alpine", "include_matches": "true"}, wantError: "include_matches argument must be a boolean"},
		{name: "invalid severity type", arguments: map[string]any{"image_name": "nginx:alpine", "severity": 123}, wantError: "severity argument must be a string"},
		{name: "invalid severity value typo", arguments: map[string]any{"image_name": "nginx:alpine", "severity": "Hihg"}, wantError: "invalid severity \"Hihg\": must be one of Critical, High, Medium, Low, Negligible, Unknown"},
		{name: "invalid severity value bogus", arguments: map[string]any{"image_name": "nginx:alpine", "severity": "bogus"}, wantError: "invalid severity \"bogus\": must be one of Critical, High, Medium, Low, Negligible, Unknown"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := ksServer.CallTool(context.Background(), "scan_container_image", test.arguments)
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.True(t, result.IsError)
			assert.Equal(t, test.wantError, toolResultText(t, result))
		})
	}
}

func TestValidateImageReference(t *testing.T) {
	invalidImages := []struct {
		name      string
		imageName string
	}{
		{name: "dir prefix", imageName: "dir:/"},
		{name: "file prefix", imageName: "file:/etc/passwd"},
		{name: "sbom prefix", imageName: "sbom:/some/file"},
		{name: "purl prefix", imageName: "purl:/etc/passwd"},
		{name: "oci-dir prefix", imageName: "oci-dir:/path"},
		{name: "docker-archive prefix", imageName: "docker-archive:/path"},
		{name: "absolute path", imageName: "/etc/shadow"},
		{name: "relative path dot slash", imageName: "./local-image"},
		{name: "parent path dot dot slash", imageName: "../parent-dir"},
		{name: "invalid characters", imageName: "invalid reference with spaces"},
	}

	for _, tt := range invalidImages {
		t.Run("rejects "+tt.name, func(t *testing.T) {
			err := validateImageReference(tt.imageName)
			require.Error(t, err)
		})
	}

	validImages := []string{
		"nginx:alpine",
		"gcr.io/distroless/static:latest",
		"ubuntu@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	for _, img := range validImages {
		t.Run("accepts "+img, func(t *testing.T) {
			err := validateImageReference(img)
			require.NoError(t, err)
		})
	}
}

func TestProcessMatches(t *testing.T) {
	// Import models for presenter matches
	matches := []models.Match{
		{
			Vulnerability: models.Vulnerability{
				VulnerabilityMetadata: models.VulnerabilityMetadata{
					ID:       "CVE-2024-0001",
					Severity: "High",
				},
			},
		},
		{
			// Duplicate CVE match across different package location
			Vulnerability: models.Vulnerability{
				VulnerabilityMetadata: models.VulnerabilityMetadata{
					ID:       "CVE-2024-0001",
					Severity: "High",
				},
			},
		},
		{
			// Lowercase severity
			Vulnerability: models.Vulnerability{
				VulnerabilityMetadata: models.VulnerabilityMetadata{
					ID:       "CVE-2024-0002",
					Severity: "critical",
				},
			},
		},
		{
			// Missing severity
			Vulnerability: models.Vulnerability{
				VulnerabilityMetadata: models.VulnerabilityMetadata{
					ID:       "CVE-2024-0003",
					Severity: "",
				},
			},
		},
		{
			// Low severity
			Vulnerability: models.Vulnerability{
				VulnerabilityMetadata: models.VulnerabilityMetadata{
					ID:       "CVE-2024-0004",
					Severity: "Low",
				},
			},
		},
	}

	t.Run("default summary mode without matches array", func(t *testing.T) {
		resp := processMatches("nginx:alpine", matches, false, "")

		assert.Equal(t, "nginx:alpine", resp.Image)
		assert.Equal(t, 4, resp.TotalUniqueCVEs)
		assert.Nil(t, resp.Matches) // omitted when includeMatches is false

		// Verify severity counts match total unique CVEs
		totalCount := 0
		for _, count := range resp.Severities {
			totalCount += count
		}
		assert.Equal(t, resp.TotalUniqueCVEs, totalCount)

		assert.Equal(t, 1, resp.Severities["High"])
		assert.Equal(t, 1, resp.Severities["Critical"])
		assert.Equal(t, 1, resp.Severities["Unknown"])
		assert.Equal(t, 1, resp.Severities["Low"])
	})

	t.Run("include matches mode", func(t *testing.T) {
		resp := processMatches("nginx:alpine", matches, true, "")

		assert.Equal(t, 4, resp.TotalUniqueCVEs)
		assert.Len(t, resp.Matches, 5) // all 5 raw matches included
	})

	t.Run("severity filtering", func(t *testing.T) {
		resp := processMatches("nginx:alpine", matches, false, "High")

		// Only Critical and High should remain (CVE-2024-0001 and CVE-2024-0002)
		assert.Equal(t, 2, resp.TotalUniqueCVEs)
		assert.Equal(t, 1, resp.Severities["High"])
		assert.Equal(t, 1, resp.Severities["Critical"])
		assert.Equal(t, 0, resp.Severities["Low"])
		assert.Equal(t, 0, resp.Severities["Unknown"])
	})
}
