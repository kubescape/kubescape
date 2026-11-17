package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSuggestFix_Registered(t *testing.T) {
	ksServer := &KubescapeMcpserver{s: server.NewMCPServer("kubescape-test", "test")}
	registerTools(ksServer)

	resp := ksServer.s.HandleMessage(context.Background(), json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	raw, err := json.Marshal(resp)
	require.NoError(t, err)

	var listed struct {
		Result struct {
			Tools []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
				InputSchema struct {
					Properties map[string]any `json:"properties"`
					Required   []string       `json:"required"`
				} `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(raw, &listed))

	var found bool
	for _, tool := range listed.Result.Tools {
		if tool.Name == "suggest_fix" {
			found = true
			assert.NotEmpty(t, tool.Description)
			assert.Contains(t, tool.InputSchema.Properties, "path")
			assert.Contains(t, tool.InputSchema.Properties, "report_path")
			assert.Contains(t, tool.InputSchema.Properties, "base_path")
			assert.Contains(t, tool.InputSchema.Properties, "control_ids")
			// control_ids must NOT be required for suggest_fix
			assert.NotContains(t, tool.InputSchema.Required, "control_ids")
			break
		}
	}
	assert.True(t, found, "suggest_fix tool was not registered")
}

func TestSuggestFix_MutuallyExclusiveArguments(t *testing.T) {
	ksServer := &KubescapeMcpserver{s: server.NewMCPServer("kubescape-test", "test")}
	registerTools(ksServer)

	t.Run("neither path nor report_path", func(t *testing.T) {
		res, err := ksServer.CallTool(context.Background(), "suggest_fix", map[string]any{})
		require.NoError(t, err)
		assert.True(t, res.IsError)
		assert.Contains(t, res.Content[0].(mcp.TextContent).Text, "path argument is required")
	})

	t.Run("both path and report_path", func(t *testing.T) {
		res, err := ksServer.CallTool(context.Background(), "suggest_fix", map[string]any{
			"path":        "/manifest.yaml",
			"report_path": "/report.json",
		})
		require.NoError(t, err)
		assert.True(t, res.IsError)
		assert.Contains(t, res.Content[0].(mcp.TextContent).Text, "mutually exclusive")
	})

	t.Run("path and base_path", func(t *testing.T) {
		res, err := ksServer.CallTool(context.Background(), "suggest_fix", map[string]any{
			"path":      "/manifest.yaml",
			"base_path": "/dir",
		})
		require.NoError(t, err)
		assert.True(t, res.IsError)
		assert.Contains(t, res.Content[0].(mcp.TextContent).Text, "base_path applies only with report_path")
	})
}

func TestSuggestFix_DryRunUnifiedDiff(t *testing.T) {
	tmpDir := t.TempDir()
	manifestName := "deployment.yaml"
	manifestPath := filepath.Join(tmpDir, manifestName)
	originalYAML := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
  namespace: default
spec:
  template:
    spec:
      containers:
      - name: nginx
        image: nginx:1.14.2
`
	require.NoError(t, os.WriteFile(manifestPath, []byte(originalYAML), 0600))

	resObj := remediationResource(tmpDir, manifestName, "Deployment", "nginx", 0)
	rule := remediationFailedRuleWithFix("spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation", "false")
	ctrl := remediationFailedControl("C-0017", "allowPrivilegeEscalation", rule)
	report := remediationReport(tmpDir, resObj, ctrl)

	reportBytes, err := json.Marshal(report)
	require.NoError(t, err)

	stubScanOutcome(t, &iacScanOutcome{ReportJSON: reportBytes, Degraded: false})

	ksServer := &KubescapeMcpserver{s: server.NewMCPServer("kubescape-test", "test"), workspaceDir: tmpDir}
	registerTools(ksServer)

	res, err := ksServer.CallTool(context.Background(), "suggest_fix", map[string]any{
		"path":        manifestName,
		"control_ids": "C-0017",
	})
	require.NoError(t, err)
	require.False(t, res.IsError, "tool call returned error: %v", res)

	text := res.Content[0].(mcp.TextContent).Text
	var resp suggestFixResponse
	require.NoError(t, json.Unmarshal([]byte(text), &resp))

	// File on disk must NOT be modified in suggest_fix!
	currentContent, err := os.ReadFile(manifestPath)
	require.NoError(t, err)
	assert.Equal(t, originalYAML, string(currentContent), "suggest_fix must never modify file on disk")

	// Diff assertions
	assert.Equal(t, 1, resp.FilesChanged)
	assert.Equal(t, 1, resp.ResourcesChanged)
	assert.Equal(t, 1, resp.FixedControlInstances)
	assert.Contains(t, resp.Diff, "diff --git")
	assert.Contains(t, resp.Diff, "allowPrivilegeEscalation: false")
	assert.Len(t, resp.Files, 1)
	assert.Equal(t, manifestPath, resp.Files[0].FilePath)
	assert.Contains(t, resp.Files[0].Diff, "allowPrivilegeEscalation: false")
	assert.NotEmpty(t, resp.Files[0].AppliedExpressions)

	// Items assertion
	require.Len(t, resp.Items, 1)
	assert.Equal(t, resObj.GetID(), resp.Items[0].ResourceID)
	assert.Equal(t, "C-0017", resp.Items[0].Control.ID)
	assert.Equal(t, classPatchAvailable, resp.Items[0].Classification)
}

func TestSuggestFix_FromReport(t *testing.T) {
	tmpDir := t.TempDir()
	manifestName := "deployment.yaml"
	manifestPath := filepath.Join(tmpDir, manifestName)
	originalYAML := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-pod
  namespace: default
spec:
  template:
    spec:
      containers:
      - name: test
        image: alpine
`
	require.NoError(t, os.WriteFile(manifestPath, []byte(originalYAML), 0600))

	resObj := remediationResource(tmpDir, manifestName, "Deployment", "test-pod", 0)
	rule := remediationFailedRuleWithFix("spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation", "false")
	ctrl := remediationFailedControl("C-0017", "allowPrivilegeEscalation", rule)
	report := remediationReport(tmpDir, resObj, ctrl)

	reportBytes, err := json.Marshal(report)
	require.NoError(t, err)

	reportPath := filepath.Join(tmpDir, "report.json")
	require.NoError(t, os.WriteFile(reportPath, reportBytes, 0600))

	ksServer := &KubescapeMcpserver{s: server.NewMCPServer("kubescape-test", "test"), workspaceDir: tmpDir}
	registerTools(ksServer)

	res, err := ksServer.CallTool(context.Background(), "suggest_fix", map[string]any{
		"report_path": "report.json",
		"base_path":   tmpDir,
	})
	require.NoError(t, err)
	require.False(t, res.IsError, "tool call returned error: %v", res)

	text := res.Content[0].(mcp.TextContent).Text
	var resp suggestFixResponse
	require.NoError(t, json.Unmarshal([]byte(text), &resp))

	assert.Equal(t, 1, resp.FilesChanged)
	assert.Contains(t, resp.Diff, "allowPrivilegeEscalation: false")
	assert.Len(t, resp.Items, 1)
}

func TestSuggestFix_UnfixedControlsReported(t *testing.T) {
	tmpDir := t.TempDir()
	manifestName := "pod.yaml"
	manifestPath := filepath.Join(tmpDir, manifestName)
	originalYAML := `apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: default
spec:
  hostNetwork: true
  containers:
  - name: test
    image: alpine
`
	require.NoError(t, os.WriteFile(manifestPath, []byte(originalYAML), 0600))

	resObj := remediationResource(tmpDir, manifestName, "Pod", "test-pod", 0)
	rule := remediationFailedRuleNoFix()
	ctrl := remediationFailedControl("C-0041", "hostNetwork", rule)
	report := remediationReport(tmpDir, resObj, ctrl)

	reportBytes, err := json.Marshal(report)
	require.NoError(t, err)

	reportPath := filepath.Join(tmpDir, "report.json")
	require.NoError(t, os.WriteFile(reportPath, reportBytes, 0600))

	ksServer := &KubescapeMcpserver{s: server.NewMCPServer("kubescape-test", "test"), workspaceDir: tmpDir}
	registerTools(ksServer)

	res, err := ksServer.CallTool(context.Background(), "suggest_fix", map[string]any{
		"report_path": "report.json",
		"base_path":   tmpDir,
		"control_ids": "C-0041",
	})
	require.NoError(t, err)
	require.False(t, res.IsError)

	text := res.Content[0].(mcp.TextContent).Text
	var resp suggestFixResponse
	require.NoError(t, json.Unmarshal([]byte(text), &resp))

	assert.Equal(t, 0, resp.FilesChanged)
	assert.Empty(t, resp.Diff)
	require.NotEmpty(t, resp.UnfixedControls)
	assert.Equal(t, "C-0041", resp.UnfixedControls[0].ControlID)
	require.Len(t, resp.Items, 1)
	assert.Equal(t, classManual, resp.Items[0].Classification)
}

func TestSuggestFix_RealDefaultScan(t *testing.T) {
	tmpDir := t.TempDir()
	manifestName := "privileged-pod.yaml"
	manifestPath := filepath.Join(tmpDir, manifestName)
	require.NoError(t, os.WriteFile(manifestPath, []byte(privilegedPodManifest), 0600))

	ksServer := &KubescapeMcpserver{
		s:            server.NewMCPServer("kubescape-test", "test"),
		policyGetter: getSharedLiveClusterPolicyGetter(t),
		workspaceDir: tmpDir,
	}
	if _, err := ksServer.policyGetter.GetFramework("allcontrols"); err != nil {
		if sharedLiveClusterPolicyFallback {
			t.Skipf("skipping test due to missing allcontrols framework: %v", err)
		}
		t.Fatalf("missing allcontrols framework: %v", err)
	}
	registerTools(ksServer)

	// Call suggest_fix without control_ids to exercise the real default allcontrols scan path
	res, err := ksServer.CallTool(context.Background(), "suggest_fix", map[string]any{
		"path": manifestName,
	})
	require.NoError(t, err)
	require.False(t, res.IsError, "tool call returned error: %v", res)

	text := res.Content[0].(mcp.TextContent).Text
	var resp suggestFixResponse
	require.NoError(t, json.Unmarshal([]byte(text), &resp))

	// Because allcontrols was evaluated, items should report findings for the privileged pod
	assert.NotEmpty(t, resp.Items, "expected evaluated items from default allcontrols scan")
	assert.NotNil(t, resp.Report)

	// Must never modify file on disk
	content, err := os.ReadFile(manifestPath)
	require.NoError(t, err)
	assert.Equal(t, privilegedPodManifest, string(content), "suggest_fix must never modify file on disk")
}
