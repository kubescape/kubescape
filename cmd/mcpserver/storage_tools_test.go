package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	storagev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	storagefake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var storageToolNames = []string{
	"list_vulnerability_manifests",
	"list_vulnerabilities_in_manifest",
	"list_vulnerability_matches_for_cve",
	"list_sboms",
	"list_sbom_packages",
	"list_configuration_security_scan_manifests",
	"get_configuration_security_scan_manifest",
	"list_container_profiles",
	"get_container_profile",
}

// The registered read tools are storage's, marked read-only, and describe
// the CLI's namespace defaults rather than the in-cluster endpoint's.
func TestStorageToolsRegistration(t *testing.T) {
	ksServer := newRegisteredStorageToolTestServer()
	createRuntimeToolsAndResources(ksServer)
	for _, name := range storageToolNames {
		t.Run(name, func(t *testing.T) {
			tool := ksServer.s.GetTool(name)
			require.NotNil(t, tool)
			a := tool.Tool.Annotations
			require.NotNil(t, a.ReadOnlyHint)
			require.NotNil(t, a.DestructiveHint)
			assert.True(t, *a.ReadOnlyHint)
			assert.False(t, *a.DestructiveHint)
			description := tool.Tool.InputSchema.Properties["namespace"].(map[string]any)["description"].(string)
			assert.NotContains(t, description, "endpoint's URL")
		})
	}
}

// With no namespace, a list reads every namespace, and a get of a
// vulnerability manifest or SBOM reads kubescape.
func TestStorageToolsDefaultNamespaces(t *testing.T) {
	ks := &KubescapeMcpserver{ksClient: storagefake.NewClientset(
		&storagev1beta1.VulnerabilityManifest{ObjectMeta: objectMeta("kubescape", "nginx")},
		&storagev1beta1.VulnerabilityManifest{ObjectMeta: objectMeta("other", "redis")},
		&storagev1beta1.SBOMSyft{ObjectMeta: objectMeta("kubescape", "nginx")},
	).SpdxV1beta1()}

	result, err := ks.CallTool(context.Background(), "list_vulnerability_manifests", map[string]any{})
	require.NoError(t, err)
	require.False(t, result.IsError, toolResultText(t, result))
	var list struct {
		VulnerabilityManifests struct {
			Manifests []struct {
				Namespace   string `json:"namespace"`
				ResourceURI string `json:"resource_uri"`
			} `json:"manifests"`
		} `json:"vulnerability_manifests"`
		AvailableTemplates map[string]string `json:"available_templates"`
	}
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &list))
	require.Len(t, list.VulnerabilityManifests.Manifests, 2)
	assert.Equal(t, "kubescape://vulnerability-manifests/kubescape/nginx", list.VulnerabilityManifests.Manifests[0].ResourceURI)
	assert.Equal(t, "other", list.VulnerabilityManifests.Manifests[1].Namespace)
	assert.Contains(t, list.AvailableTemplates, "vulnerability_manifest_cve_list")

	for tool, args := range map[string]map[string]any{
		"list_vulnerabilities_in_manifest":   {"manifest_name": "nginx"},
		"list_vulnerability_matches_for_cve": {"manifest_name": "nginx", "cve_id": "CVE-2026-0001"},
		"list_sbom_packages":                 {"sbom_name": "nginx"},
	} {
		t.Run(tool, func(t *testing.T) {
			result, err := ks.CallTool(context.Background(), tool, args)
			require.NoError(t, err)
			assert.False(t, result.IsError, toolResultText(t, result))
		})
	}
}

// A storage client that cannot be built is a K8S_CLIENT_ERROR tool error, as
// for the CLI's other tools.
func TestStorageToolsClientError(t *testing.T) {
	ks := &KubescapeMcpserver{ksClientInit: func() (spdxv1beta1.SpdxV1beta1Interface, error) {
		return nil, errors.New("no kubeconfig")
	}}
	for _, name := range storageToolNames {
		t.Run(name, func(t *testing.T) {
			result, err := ks.CallTool(context.Background(), name, map[string]any{
				"manifest_name": "m", "sbom_name": "s", "profile_name": "p", "cve_id": "CVE-2026-0001",
			})
			require.NoError(t, err)
			require.True(t, result.IsError)
			var toolErr ToolError
			require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
			assert.Equal(t, ErrCodeK8sClientError, toolErr.Code)
			assert.Contains(t, toolErr.Message, "no kubeconfig")
		})
	}
}

// String arguments are trimmed, as for the CLI's other tools: a padded name
// still finds its object, and a blank required one is missing.
func TestStorageToolsTrimStringArguments(t *testing.T) {
	ks := &KubescapeMcpserver{ksClient: storagefake.NewClientset(&storagev1beta1.VulnerabilityManifest{
		ObjectMeta: objectMeta("kubescape", "nginx"),
		Spec: storagev1beta1.VulnerabilityManifestSpec{Payload: storagev1beta1.GrypeDocument{Matches: []storagev1beta1.Match{
			vulnMatch("CVE-2026-0001", "High", "openssl", "3.0.2", "fixed", "3.0.7"),
		}}},
	}).SpdxV1beta1()}

	result, err := ks.CallTool(context.Background(), "list_vulnerability_matches_for_cve",
		map[string]any{"namespace": " kubescape ", "manifest_name": " nginx\n", "cve_id": "\tCVE-2026-0001 "})
	require.NoError(t, err)
	require.False(t, result.IsError, toolResultText(t, result))
	var page struct {
		Total int `json:"total"`
	}
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &page))
	assert.Equal(t, 1, page.Total)

	result, err = ks.CallTool(context.Background(), "list_vulnerabilities_in_manifest", map[string]any{"manifest_name": "   "})
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.Contains(t, toolResultText(t, result), "manifest_name is required")
}
