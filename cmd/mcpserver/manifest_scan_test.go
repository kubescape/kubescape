package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/opa-utils/reporthandling"
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

const sampleMultiPrivilegedPodManifest = `apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod-1
  namespace: default
spec:
  containers:
  - name: myapp1
    image: nginx
    securityContext:
      privileged: true
---
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod-2
  namespace: default
spec:
  containers:
  - name: myapp2
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

func TestManifestScan_CallToolMatchesFileScope(t *testing.T) {
	const pod = `apiVersion: v1
kind: Pod
metadata:
  name: sample-web
  namespace: default
spec:
  containers:
  - name: web
    image: nginx:1.27
`
	manifestRule := reporthandling.PolicyRule{
		PortalBase:   armotypes.PortalBase{Name: "pod-owner-label"},
		RuleLanguage: reporthandling.RegoLanguage,
		Match:        []reporthandling.RuleMatchObjects{{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Pod"}}},
		Rule: `package armo_builtins
deny contains alert if {
    pod := input[_]
    not pod.metadata.labels.owner
    alert := {"alertMessage": "Missing owner label", "alertObject": {"k8sApiObjects": [pod]}}
}`,
	}
	clusterRule := manifestRule
	clusterRule.Name = "cluster-pod-check"
	clusterRule.Rule = "package armo_builtins\ndeny := []"
	framework := reporthandling.Framework{
		PortalBase: armotypes.PortalBase{Name: "manifest-scope-test"},
		Controls: []reporthandling.Control{
			{ControlID: "C-0001", BaseScore: 1, Rules: []reporthandling.PolicyRule{manifestRule}},
			{
				ControlID: "C-0002",
				BaseScore: 1,
				ScanningScope: &reporthandling.ScanningScope{
					Matches: []reporthandling.ScanningScopeType{reporthandling.ScopeCluster},
				},
				Rules: []reporthandling.PolicyRule{clusterRule},
			},
		},
	}

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "framework.json")
	require.NoError(t, getter.SaveInFile(framework, policyPath))
	manifestPath := filepath.Join(dir, "pod.yaml")
	require.NoError(t, os.WriteFile(manifestPath, []byte(pod), 0o600))
	ksServer := &KubescapeMcpserver{
		policyGetter: getter.NewLoadPolicy([]string{policyPath}),
		workspaceDir: dir,
	}
	scan := func(tool, inputName, input string) scanResponse {
		t.Helper()
		result, err := ksServer.CallTool(context.Background(), tool, map[string]any{
			inputName:   input,
			"framework": framework.Name,
		})
		require.NoError(t, err)
		responseText := toolResultText(t, result)
		require.False(t, result.IsError, responseText)
		var response scanResponse
		require.NoError(t, json.Unmarshal([]byte(responseText), &response))
		return response
	}

	file := scan("scan_local_iac", "path", manifestPath)
	require.Equal(t, 1, file.TotalControls)
	require.Equal(t, 1, file.TotalFailed)
	require.NotNil(t, file.ComplianceScore)
	inline := scan("scan_manifest", "manifest", pod)
	assert.Equal(t, file.TotalControls, inline.TotalControls)
	assert.Equal(t, file.TotalFailed, inline.TotalFailed)
	require.NotNil(t, inline.ComplianceScore)
	assert.Equal(t, *file.ComplianceScore, *inline.ComplianceScore)
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

	// CallTool with manifest alone (framework and control_ids omitted: defaults to nsa)
	result, err = ksServer.CallTool(context.Background(), "scan_manifest", map[string]any{
		"manifest": samplePrivilegedPodManifest,
	})
	require.NoError(t, err)
	require.False(t, result.IsError)
	text = toolResultText(t, result)
	require.Contains(t, text, `"framework_name":"NSA"`)
	require.NotContains(t, text, `"total_failed":0`)

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

func TestManifestScan_CallTool_WithoutControlIDs(t *testing.T) {
	ksServer := &KubescapeMcpserver{
		s:            server.NewMCPServer("kubescape-test", "test"),
		policyGetter: getSharedLiveClusterPolicyGetter(t),
	}
	registerTools(ksServer)

	t.Run("manifest alone defaults to nsa framework", func(t *testing.T) {
		result, err := ksServer.CallTool(context.Background(), "scan_manifest", map[string]any{
			"manifest": samplePrivilegedPodManifest,
		})
		require.NoError(t, err)
		require.False(t, result.IsError)

		var resp scanResponse
		err = json.Unmarshal([]byte(toolResultText(t, result)), &resp)
		require.NoError(t, err)

		assert.True(t, strings.EqualFold(resp.FrameworkName, "nsa"), "expected default framework to be nsa")
		assert.Greater(t, resp.TotalFailed, 0, "privileged pod should have failed controls in default nsa framework")
		assert.NotEmpty(t, resp.FailedResources)
	})

	t.Run("manifest with explicit framework only", func(t *testing.T) {
		result, err := ksServer.CallTool(context.Background(), "scan_manifest", map[string]any{
			"manifest":  samplePrivilegedPodManifest,
			"framework": "mitre",
		})
		require.NoError(t, err)
		require.False(t, result.IsError)

		var resp scanResponse
		err = json.Unmarshal([]byte(toolResultText(t, result)), &resp)
		require.NoError(t, err)

		assert.True(t, strings.EqualFold(resp.FrameworkName, "mitre"), "expected framework to be mitre")
		assert.Greater(t, resp.TotalFailed, 0)
		assert.NotEmpty(t, resp.FailedResources)
	})

	t.Run("valid JSON manifest alone defaults to nsa framework", func(t *testing.T) {
		result, err := ksServer.CallTool(context.Background(), "scan_manifest", map[string]any{
			"manifest": sampleValidJSONManifest,
		})
		require.NoError(t, err)
		require.False(t, result.IsError)

		var resp scanResponse
		err = json.Unmarshal([]byte(toolResultText(t, result)), &resp)
		require.NoError(t, err)

		assert.True(t, strings.EqualFold(resp.FrameworkName, "nsa"))
		assert.Greater(t, resp.TotalFailed, 0)
	})

	t.Run("manifest alone with filters", func(t *testing.T) {
		// Baseline with no limit and no severity filter: both resources fail
		baseResult, err := ksServer.CallTool(context.Background(), "scan_manifest", map[string]any{
			"manifest": sampleMultiPrivilegedPodManifest,
		})
		require.NoError(t, err)
		require.False(t, baseResult.IsError)

		var baseResp scanResponse
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, baseResult)), &baseResp))
		assert.True(t, strings.EqualFold(baseResp.FrameworkName, "nsa"))
		assert.Equal(t, 2, baseResp.TotalFailed, "expected both privileged pods to fail")
		assert.Equal(t, 2, baseResp.ReturnedFailed)
		assert.Len(t, baseResp.FailedResources, 2)
		assert.False(t, baseResp.Truncated)

		// limit: 1 restricts returned results to 1 while reporting total_failed=2
		limitResult, err := ksServer.CallTool(context.Background(), "scan_manifest", map[string]any{
			"manifest": sampleMultiPrivilegedPodManifest,
			"limit":    1,
		})
		require.NoError(t, err)
		require.False(t, limitResult.IsError)

		var limitResp scanResponse
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, limitResult)), &limitResp))
		assert.Equal(t, 2, limitResp.TotalFailed)
		assert.Equal(t, 1, limitResp.ReturnedFailed)
		assert.Len(t, limitResp.FailedResources, 1, "limit: 1 must restrict failed_resources to 1 item")
		assert.True(t, limitResp.Truncated, "truncated must be true when limit < total_failed")

		// min_severity: "High" retains the High-severity C-0017 failure on privileged pods
		highResult, err := ksServer.CallTool(context.Background(), "scan_manifest", map[string]any{
			"manifest":     sampleMultiPrivilegedPodManifest,
			"min_severity": "High",
			"limit":        1,
		})
		require.NoError(t, err)
		require.False(t, highResult.IsError)

		var highResp scanResponse
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, highResult)), &highResp))
		assert.Equal(t, 2, highResp.TotalFailed)
		assert.Equal(t, 1, highResp.ReturnedFailed)
		assert.Len(t, highResp.FailedResources, 1)
		assert.True(t, highResp.Truncated)
		assert.Less(t, highResp.TotalControls, baseResp.TotalControls, "min_severity filter must reduce evaluated control count")

		// min_severity: "Critical" excludes the High/Medium/Low failures, yielding 0 failed resources
		critResult, err := ksServer.CallTool(context.Background(), "scan_manifest", map[string]any{
			"manifest":     sampleMultiPrivilegedPodManifest,
			"min_severity": "Critical",
		})
		require.NoError(t, err)
		require.False(t, critResult.IsError)

		var critResp scanResponse
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, critResult)), &critResp))
		assert.Equal(t, 0, critResp.TotalFailed, "min_severity: Critical must exclude lower-severity failures")
		assert.Equal(t, 0, critResp.ReturnedFailed)
		assert.Empty(t, critResp.FailedResources)
		assert.False(t, critResp.Truncated)
		assert.Less(t, critResp.TotalControls, highResp.TotalControls)
	})
}
