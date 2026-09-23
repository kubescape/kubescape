package mcpserver

import (
	"context"
	"encoding/json"
	"testing"

	storagev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	storagefake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAgentRuntimeStoredFindingsThroughMCP(t *testing.T) {
	for _, test := range []struct {
		kind, group, version, controlID, path, fixValue string
	}{
		{"Sandbox", "agents.x-k8s.io", "v1beta1", "C-0297", "spec.podTemplate.spec.runtimeClassName", "gvisor"},
		{"SandboxTemplate", "extensions.agents.x-k8s.io", "v1beta1", "C-0314", "spec.networkPolicyManagement", "Managed"},
		{"WorkerPool", "ate.dev", "v1alpha1", "C-0317", "spec.template.resources.limits.cpu", "1"},
	} {
		t.Run(test.kind, func(t *testing.T) {
			manifest := &storagev1beta1.WorkloadConfigurationScan{
				ObjectMeta: metav1.ObjectMeta{Name: "agent-runtime", Namespace: "agents"},
				Spec: storagev1beta1.WorkloadConfigurationScanSpec{
					RelatedObjects: []storagev1beta1.WorkloadScanRelatedObject{{
						APIGroup: test.group, APIVersion: test.version, Kind: test.kind, Namespace: "agents", Name: "code-runner",
					}},
					Controls: map[string]storagev1beta1.ScannedControl{
						"C-AGENT-PASSED": {
							ControlID: "C-AGENT-PASSED", Name: "Passing fixture control",
							Status: storagev1beta1.ScannedControlStatus{Status: "passed"},
						},
						"C-AGENT-SKIPPED": {
							ControlID: "C-AGENT-SKIPPED", Name: "Skipped fixture control",
							Status: storagev1beta1.ScannedControlStatus{Status: "skipped", SubStatus: "not-evaluated", Info: "fixture input unavailable"},
						},
						test.controlID: {
							ControlID: test.controlID, Name: "Agent Runtime posture",
							Status:   storagev1beta1.ScannedControlStatus{Status: "failed"},
							Severity: storagev1beta1.ControlSeverity{Severity: "High", ScoreFactor: 7},
							Rules: []storagev1beta1.ScannedControlRule{{
								Name:   "agent-runtime-rule",
								Status: storagev1beta1.RuleStatus{Status: "failed"},
								Paths:  []storagev1beta1.RulePath{{FailedPath: test.path, FixPath: test.path, FixPathValue: test.fixValue}},
							}},
						},
					},
				},
			}
			otherNamespace := manifest.DeepCopy()
			otherNamespace.Namespace = "other"
			client := storagefake.NewClientset(manifest, otherNamespace)
			ksServer := &KubescapeMcpserver{ksClient: client.SpdxV1beta1()}
			ctx := context.Background()
			listed, err := ksServer.CallTool(ctx, "list_configuration_security_scan_manifests", map[string]any{"namespace": "agents"})
			require.NoError(t, err)
			var listing struct {
				Manifests struct {
					Items []struct {
						Name      string `json:"manifest_name"`
						Namespace string `json:"namespace"`
						URI       string `json:"resource_uri"`
					} `json:"manifests"`
				} `json:"configuration_manifests"`
			}
			require.NoError(t, json.Unmarshal([]byte(toolResultText(t, listed)), &listing))
			require.Len(t, listing.Manifests.Items, 1)
			item := listing.Manifests.Items[0]
			assert.Equal(t, manifest.Name, item.Name)
			assert.Equal(t, "agents", item.Namespace)
			assert.Equal(t, "kubescape://configuration-manifests/agents/agent-runtime", item.URI)

			got, err := ksServer.CallTool(ctx, "get_configuration_security_scan_manifest", map[string]any{"namespace": item.Namespace, "manifest_name": item.Name})
			require.NoError(t, err)
			var decoded storagev1beta1.WorkloadConfigurationScan
			require.NoError(t, json.Unmarshal([]byte(toolResultText(t, got)), &decoded))
			assert.Equal(t, manifest.Spec, decoded.Spec)
			assert.Equal(t, manifest.Namespace, decoded.Namespace)

			request := mcp.ReadResourceRequest{}
			request.Params.URI = item.URI
			contents, err := ksServer.ReadConfigurationResource(ctx, request)
			require.NoError(t, err)
			require.Len(t, contents, 1)
			content, ok := contents[0].(mcp.TextResourceContents)
			require.True(t, ok)
			assert.JSONEq(t, toolResultText(t, got), content.Text)
		})
	}
}
