package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const samplePrivilegedPodManifest = `apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
  namespace: default
spec:
  containers:
  - name: myapp
    image: nginx
    securityContext:
      privileged: true
`

const sampleValidJSONManifest = `{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "json-pod",
    "namespace": "default"
  },
  "spec": {
    "containers": [
      {
        "name": "app",
        "image": "nginx",
        "securityContext": {
          "privileged": true
        }
      }
    ]
  }
}`

func TestManifestScan_Validation(t *testing.T) {
	ksServer := &KubescapeMcpserver{
		policyGetter: getter.NewDownloadReleasedPolicy(),
	}

	// 1. Empty string
	_, err := ksServer.runManifestScan(context.Background(), "", "nsa", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "manifest content cannot be empty")

	// 2. Whitespace only
	_, err = ksServer.runManifestScan(context.Background(), "   \n\t  ", "nsa", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "manifest content cannot be empty")

	// 3. Oversized manifest
	oversized := strings.Repeat("x", maxManifestBytes+10)
	_, err = ksServer.runManifestScan(context.Background(), oversized, "nsa", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "manifest exceeds maximum allowed size")

	// 4. Non-Kubernetes YAML
	_, err = ksServer.runManifestScan(context.Background(), "hello: world\nfoo: bar\n", "nsa", nil)
	require.Error(t, err)
}

func TestManifestScan_ValidYAML(t *testing.T) {
	ksServer := &KubescapeMcpserver{
		policyGetter: getSharedLiveClusterPolicyGetter(t),
	}

	respBytes, err := ksServer.runManifestScan(context.Background(), samplePrivilegedPodManifest, "nsa", nil)
	require.NoError(t, err)

	var resp scanResponse
	err = json.Unmarshal(respBytes, &resp)
	require.NoError(t, err)

	assert.True(t, strings.EqualFold(resp.FrameworkName, "nsa"))
	assert.Greater(t, resp.TotalFailed, 0, "privileged pod should have failed controls in nsa")
	assert.NotEmpty(t, resp.FailedResources)
}

func TestManifestScan_SpecificControls(t *testing.T) {
	ksServer := &KubescapeMcpserver{
		policyGetter: getSharedLiveClusterPolicyGetter(t),
	}

	// C-0017 evaluates host privileged container
	respBytes, err := ksServer.runManifestScan(context.Background(), samplePrivilegedPodManifest, "", []string{"C-0017"})
	require.NoError(t, err)

	var resp scanResponse
	err = json.Unmarshal(respBytes, &resp)
	require.NoError(t, err)

	assert.Equal(t, 1, resp.TotalControls)
	assert.Equal(t, 1, resp.TotalFailed)
	assert.Len(t, resp.FailedResources, 1)
}

func TestManifestScan_ValidJSON(t *testing.T) {
	ksServer := &KubescapeMcpserver{
		policyGetter: getSharedLiveClusterPolicyGetter(t),
	}

	respBytes, err := ksServer.runManifestScan(context.Background(), sampleValidJSONManifest, "", []string{"C-0017"})
	require.NoError(t, err)

	var resp scanResponse
	err = json.Unmarshal(respBytes, &resp)
	require.NoError(t, err)

	assert.Equal(t, 1, resp.TotalFailed)
}

func TestManifestScan_CallTool(t *testing.T) {
	ksServer := &KubescapeMcpserver{
		s:            server.NewMCPServer("kubescape-test", "test"),
		policyGetter: getSharedLiveClusterPolicyGetter(t),
	}
	registerTools(ksServer)

	// CallTool with valid manifest
	result, err := ksServer.CallTool(context.Background(), "scan_manifest", map[string]any{
		"manifest":    samplePrivilegedPodManifest,
		"control_ids": []any{"C-0017"},
	})
	require.NoError(t, err)
	require.False(t, result.IsError)
	text := toolResultText(t, result)
	require.Contains(t, text, `"total_failed":1`)

	// CallTool with manifest and framework (control_ids omitted)
	result, err = ksServer.CallTool(context.Background(), "scan_manifest", map[string]any{
		"manifest":  samplePrivilegedPodManifest,
		"framework": "nsa",
	})
	require.NoError(t, err)
	require.False(t, result.IsError)
	text = toolResultText(t, result)
	require.Contains(t, text, `"framework_name":"NSA"`)
	require.NotContains(t, text, `"total_failed":0`)

	// CallTool with manifest preserving leading whitespace and formatting
	result, err = ksServer.CallTool(context.Background(), "scan_manifest", map[string]any{
		"manifest":    "\n" + samplePrivilegedPodManifest + "\n\n",
		"control_ids": []any{"C-0017"},
	})
	require.NoError(t, err)
	require.False(t, result.IsError)
	text = toolResultText(t, result)
	require.Contains(t, text, `"total_failed":1`)

	// CallTool with non-string manifest argument
	result, err = ksServer.CallTool(context.Background(), "scan_manifest", map[string]any{
		"manifest": 12345,
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	require.Contains(t, toolResultText(t, result), "manifest argument must be a string")

	// CallTool with empty manifest argument
	result, err = ksServer.CallTool(context.Background(), "scan_manifest", map[string]any{
		"manifest": "",
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	require.Contains(t, toolResultText(t, result), "INVALID_ARGUMENT")

	// CallTool missing required manifest argument
	result, err = ksServer.CallTool(context.Background(), "scan_manifest", map[string]any{
		"framework": "nsa",
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	require.Contains(t, toolResultText(t, result), "INVALID_ARGUMENT")
}
