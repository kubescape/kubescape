package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const explainFixtureFramework = `{
  "name": "fixture",
  "controls": [
    {
      "controlID": "C-0017",
      "name": "Immutable container filesystem",
      "description": "Mutable container filesystem can be abused to inject malicious code or data into containers. Use immutable (read-only) filesystem to limit potential attacks.",
      "remediation": "Set the filesystem of the container to read-only when possible (pod securityContext, readOnlyRootFilesystem: true).",
      "baseScore": 3.0,
      "attributes": {
        "controlTypeTags": ["security", "compliance", "smartRemediation"]
      }
    },
    {
      "controlID": "C-0041",
      "name": "HostNetwork access",
      "description": "Containers should not share the host network namespace.",
      "remediation": "Do not set hostNetwork to true.",
      "baseScore": 7.0,
      "attributes": {
        "controlTypeTags": ["security"]
      }
    },
    {
      "controlID": "C-0050",
      "name": "Rule with fixPath comments but no smartRemediation",
      "description": "A control whose rule mentions fixPath in comments or empty list.",
      "baseScore": 5.0,
      "rules": [
        {
          "name": "rule-no-smart-rem",
          "rule": "# this rule does not have fixPath\nfixPaths: []"
        }
      ]
    },
    {
      "controlID": "C-0101",
      "id": "X-1",
      "name": "First ambiguous control",
      "baseScore": 5.0
    },
    {
      "controlID": "C-0102",
      "id": "X-1",
      "name": "Second ambiguous control",
      "baseScore": 5.0
    }
  ]
}`

func cautilsSummaryWith(frameworks map[string][]string) reportsummary.SummaryDetails {
	summary := reportsummary.SummaryDetails{}
	for name, ids := range frameworks {
		controls := reportsummary.ControlSummaries{}
		for _, id := range ids {
			controls[id] = reportsummary.ControlSummary{ControlID: id}
		}
		summary.Frameworks = append(summary.Frameworks, reportsummary.FrameworkSummary{Name: name, Controls: controls})
	}
	return summary
}

func newExplainTestServer(t *testing.T) *KubescapeMcpserver {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fw.json")
	require.NoError(t, os.WriteFile(path, []byte(explainFixtureFramework), 0o600))
	ks := &KubescapeMcpserver{s: server.NewMCPServer("kubescape-test", "test")}
	registerTools(ks)
	ks.startPolicyLoad(func() getter.IPolicyGetter { return getter.NewLoadPolicy([]string{path}) })
	return ks
}

func TestExplainControl_Registered(t *testing.T) {
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
		if tool.Name == "explain_control" {
			found = true
			assert.NotEmpty(t, tool.Description)
			assert.Contains(t, tool.InputSchema.Properties, "control_id")
			assert.Contains(t, tool.InputSchema.Properties, "path")
			assert.Contains(t, tool.InputSchema.Properties, "report_path")
			assert.Contains(t, tool.InputSchema.Properties, "base_path")
			assert.Contains(t, tool.InputSchema.Required, "control_id")
			assert.NotContains(t, tool.InputSchema.Required, "path")
			assert.NotContains(t, tool.InputSchema.Required, "report_path")
			break
		}
	}
	assert.True(t, found, "explain_control tool was not registered")
}

func TestExplainControl_ArgumentValidation(t *testing.T) {
	ks := newExplainTestServer(t)

	t.Run("missing control_id", func(t *testing.T) {
		res, err := ks.CallTool(context.Background(), "explain_control", map[string]any{})
		require.NoError(t, err)
		assert.True(t, res.IsError)
		assert.Contains(t, toolResultText(t, res), "control_id argument is required")
	})

	t.Run("empty control_id", func(t *testing.T) {
		res, err := ks.CallTool(context.Background(), "explain_control", map[string]any{"control_id": "   "})
		require.NoError(t, err)
		assert.True(t, res.IsError)
		assert.Contains(t, toolResultText(t, res), "control_id argument is required and cannot be empty")
	})

	t.Run("mutually exclusive path and report_path", func(t *testing.T) {
		res, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id":  "C-0017",
			"path":        "/some/manifest.yaml",
			"report_path": "/some/report.json",
		})
		require.NoError(t, err)
		assert.True(t, res.IsError)
		assert.Contains(t, toolResultText(t, res), "mutually exclusive")
	})

	t.Run("path and base_path disallowed", func(t *testing.T) {
		res, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id": "C-0017",
			"path":       "/some/manifest.yaml",
			"base_path":  "/some/base",
		})
		require.NoError(t, err)
		assert.True(t, res.IsError)
		assert.Contains(t, toolResultText(t, res), "base_path applies only with report_path")
	})

	t.Run("base_path without report_path disallowed", func(t *testing.T) {
		res, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id": "C-0017",
			"base_path":  "/some/base",
		})
		require.NoError(t, err)
		assert.True(t, res.IsError)
		assert.Contains(t, toolResultText(t, res), "base_path applies only with report_path")
	})
}

func TestExplainControl_UnknownControl(t *testing.T) {
	ks := newExplainTestServer(t)

	res, err := ks.CallTool(context.Background(), "explain_control", map[string]any{"control_id": "C-9999"})
	require.NoError(t, err)
	assert.True(t, res.IsError)

	var toolErr ToolError
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, res)), &toolErr))
	assert.Equal(t, ErrCodeInvalidArgument, toolErr.Code)
	assert.Equal(t, "control 'C-9999' not found", toolErr.Message)
	assert.Equal(t, "C-9999", toolErr.Details["control_id"])
}

func TestExplainControl_AmbiguousControl(t *testing.T) {
	ks := newExplainTestServer(t)

	res, err := ks.CallTool(context.Background(), "explain_control", map[string]any{"control_id": "X-1"})
	require.NoError(t, err)
	assert.True(t, res.IsError)

	var toolErr ToolError
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, res)), &toolErr))
	assert.Equal(t, ErrCodeInvalidArgument, toolErr.Code)
	assert.Contains(t, strings.ToLower(toolErr.Message), "x-1")
	assert.Contains(t, toolErr.Message, "C-0101, C-0102")
}

func TestExplainControl_WithoutScanContext(t *testing.T) {
	ks := newExplainTestServer(t)

	t.Run("auto-fixable control C-0017", func(t *testing.T) {
		res, err := ks.CallTool(context.Background(), "explain_control", map[string]any{"control_id": "c-0017"})
		require.NoError(t, err)
		assert.False(t, res.IsError, toolResultText(t, res))

		var resp explainControlResponse
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, res)), &resp))

		assert.Equal(t, "C-0017", resp.ControlID)
		assert.Equal(t, "Immutable container filesystem", resp.Name)
		assert.Equal(t, "Low", resp.Severity)
		assert.Contains(t, resp.Description, "Mutable container filesystem")
		assert.Contains(t, resp.Remediation, "readOnlyRootFilesystem: true")
		assert.True(t, resp.AutoFixAvailable, "C-0017 carries smartRemediation")
		assert.Nil(t, resp.FailingResources, "failing_resources must be omitted when scan context is not provided")
		assert.NotContains(t, toolResultText(t, res), "failing_resources")
	})

	t.Run("non-fixable control C-0041", func(t *testing.T) {
		res, err := ks.CallTool(context.Background(), "explain_control", map[string]any{"control_id": "C-0041"})
		require.NoError(t, err)
		assert.False(t, res.IsError, toolResultText(t, res))

		var resp explainControlResponse
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, res)), &resp))

		assert.Equal(t, "C-0041", resp.ControlID)
		assert.Equal(t, "HostNetwork access", resp.Name)
		assert.Equal(t, "High", resp.Severity)
		assert.Contains(t, resp.Description, "host network namespace")
		assert.Contains(t, resp.Remediation, "Do not set hostNetwork to true")
		assert.False(t, resp.AutoFixAvailable, "C-0041 does not have auto-fix")
		assert.Nil(t, resp.FailingResources)
	})

	t.Run("control with fixPath comment but no smartRemediation attribute", func(t *testing.T) {
		res, err := ks.CallTool(context.Background(), "explain_control", map[string]any{"control_id": "C-0050"})
		require.NoError(t, err)
		assert.False(t, res.IsError, toolResultText(t, res))

		var resp explainControlResponse
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, res)), &resp))

		assert.Equal(t, "C-0050", resp.ControlID)
		assert.False(t, resp.AutoFixAvailable, "comments mentioning fixPath must not cause false-positive auto_fix_available")
	})
}

func TestExplainControl_WithReportScanContext(t *testing.T) {
	ks := newExplainTestServer(t)
	dir := t.TempDir()

	res := remediationClusterResource("Deployment", "nginx", "default")
	res.Source = &reporthandling.Source{
		FileType:     reporthandling.SourceTypeYaml,
		Path:         dir,
		RelativePath: "deploy.yaml",
	}
	rule := resourcesresults.ResourceAssociatedRule{
		Name:   "host-network-access",
		Status: apis.StatusFailed,
		Paths: []armotypes.PosturePaths{
			{
				FailedPath: "spec.template.spec.hostNetwork",
				FixPath:    armotypes.FixPath{Path: "spec.template.spec.hostNetwork", Value: "false"},
			},
		},
	}
	ctrl := remediationFailedControl("C-0041", "HostNetwork access", rule)
	result := remediationClusterResult(res, ctrl)
	report := remediationClusterReport([]resourcesresults.Result{result}, res)
	report.Metadata.ScanMetadata.ScanningTarget = reporthandlingv2.Directory
	report.Metadata.ContextMetadata.ClusterContextMetadata = nil
	report.Metadata.ContextMetadata.DirectoryContextMetadata = &reporthandlingv2.DirectoryContextMetadata{BasePath: dir}
	reportPath := writeRemediationReport(t, dir, report, nil)

	t.Run("control with failing resources and paths", func(t *testing.T) {
		callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id":  "C-0041",
			"report_path": reportPath,
		})
		require.NoError(t, err)
		assert.False(t, callRes.IsError, toolResultText(t, callRes))

		var resp explainControlResponse
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, callRes)), &resp))

		assert.Equal(t, "C-0041", resp.ControlID)
		assert.Equal(t, "HostNetwork access", resp.Name)
		assert.Equal(t, "High", resp.Severity)
		assert.True(t, resp.AutoFixAvailable, "untagged control with valid fixPath on YAML resource must report auto-fix available from scan")
		require.NotNil(t, resp.FailingResources)
		require.Len(t, *resp.FailingResources, 1)

		failing := (*resp.FailingResources)[0]
		assert.Equal(t, "Deployment", failing.Kind)
		assert.Equal(t, "nginx", failing.Name)
		assert.Equal(t, "default", failing.Namespace)
		assert.Equal(t, "deploy.yaml", failing.FilePath)
		assert.Equal(t, []string{"spec.template.spec.hostNetwork"}, failing.FailedPaths)
	})

	t.Run("untagged control with valid fix on non-YAML resource reports auto-fix unavailable", func(t *testing.T) {
		resHelm := remediationClusterResource("Deployment", "nginx-helm", "default")
		resHelm.Source = &reporthandling.Source{
			FileType:     reporthandling.SourceTypeHelmChart,
			Path:         dir,
			RelativePath: "chart/templates/deploy.yaml",
		}
		resultHelm := remediationClusterResult(resHelm, ctrl)
		reportHelm := remediationClusterReport([]resourcesresults.Result{resultHelm}, resHelm)
		reportHelm.Metadata.ScanMetadata.ScanningTarget = reporthandlingv2.Directory
		reportHelm.Metadata.ContextMetadata.ClusterContextMetadata = nil
		reportHelm.Metadata.ContextMetadata.DirectoryContextMetadata = &reporthandlingv2.DirectoryContextMetadata{BasePath: dir}
		helmPath := writeRemediationReport(t, dir, reportHelm, nil)

		callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id":  "C-0041",
			"report_path": helmPath,
		})
		require.NoError(t, err)
		assert.False(t, callRes.IsError, toolResultText(t, callRes))

		var resp explainControlResponse
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, callRes)), &resp))

		assert.False(t, resp.AutoFixAvailable, "non-YAML resource must not report auto_fix_available even with valid fixPath")
		require.NotNil(t, resp.FailingResources)
		require.Len(t, *resp.FailingResources, 1)
		assert.Equal(t, []string{"spec.template.spec.hostNetwork"}, (*resp.FailingResources)[0].FailedPaths)
	})

	t.Run("untagged control with valid fix on cluster resource in cluster report reports auto-fix available", func(t *testing.T) {
		resCluster := remediationClusterResource("Deployment", "nginx-cluster", "default")
		resCluster.Source = nil
		resultCluster := remediationClusterResult(resCluster, ctrl)
		reportCluster := remediationClusterReport([]resourcesresults.Result{resultCluster}, resCluster)
		clusterPath := writeRemediationReport(t, dir, reportCluster, nil)

		callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id":  "C-0041",
			"report_path": clusterPath,
		})
		require.NoError(t, err)
		assert.False(t, callRes.IsError, toolResultText(t, callRes))

		var resp explainControlResponse
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, callRes)), &resp))

		assert.True(t, resp.AutoFixAvailable, "cluster resource without file source in cluster posture report must report auto-fix available from valid fix path")
	})

	t.Run("control outside report scope signals not_evaluated", func(t *testing.T) {
		callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id":  "C-0050",
			"report_path": reportPath,
		})
		require.NoError(t, err)
		assert.False(t, callRes.IsError, toolResultText(t, callRes))

		var resp explainControlResponse
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, callRes)), &resp))

		assert.Equal(t, "C-0050", resp.ControlID)
		assert.False(t, resp.AutoFixAvailable)
		assert.True(t, resp.NotEvaluated, "control not in report scope must signal not_evaluated")
		assert.Contains(t, resp.NotEvaluatedReason, "outside report scope")
		require.NotNil(t, resp.FailingResources)
		assert.Empty(t, *resp.FailingResources)
	})

	t.Run("control in scope with no failing resources", func(t *testing.T) {
		reportInScope := remediationClusterReport([]resourcesresults.Result{result}, res)
		reportInScope.SummaryDetails = cautilsSummaryWith(map[string][]string{"NSA": {"C-0041", "C-0050"}})
		inScopePath := writeRemediationReport(t, dir, reportInScope, nil)

		callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id":  "C-0050",
			"report_path": inScopePath,
		})
		require.NoError(t, err)
		assert.False(t, callRes.IsError, toolResultText(t, callRes))

		var resp explainControlResponse
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, callRes)), &resp))

		assert.Equal(t, "C-0050", resp.ControlID)
		assert.False(t, resp.AutoFixAvailable)
		assert.False(t, resp.NotEvaluated, "evaluated control with zero failures must not signal not_evaluated")
		require.NotNil(t, resp.FailingResources)
		assert.Empty(t, *resp.FailingResources)
		assert.Contains(t, toolResultText(t, callRes), `"failing_resources": []`)
	})

	t.Run("report with malformed scan coverage rejected", func(t *testing.T) {
		malformedPath := filepath.Join(dir, "malformed_cov.json")
		malformedJSON := `{"results": [], "scanCoverage": {"degraded": "not-a-bool"}}`
		require.NoError(t, os.WriteFile(malformedPath, []byte(malformedJSON), 0o600))
		callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id":  "C-0017",
			"report_path": malformedPath,
		})
		require.NoError(t, err)
		assert.True(t, callRes.IsError)
		assert.Contains(t, toolResultText(t, callRes), "invalid scan coverage")
	})

	t.Run("unreadable report_path", func(t *testing.T) {
		callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id":  "C-0017",
			"report_path": filepath.Join(dir, "non-existent.json"),
		})
		require.NoError(t, err)
		assert.True(t, callRes.IsError)
		assert.Contains(t, toolResultText(t, callRes), "cannot be read")
	})

	t.Run("invalid json in report_path", func(t *testing.T) {
		badPath := filepath.Join(dir, "corrupt.json")
		require.NoError(t, os.WriteFile(badPath, []byte("not-json"), 0o600))
		callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id":  "C-0017",
			"report_path": badPath,
		})
		require.NoError(t, err)
		assert.True(t, callRes.IsError)
		assert.Contains(t, toolResultText(t, callRes), "not a Kubescape posture report JSON")
	})

	t.Run("report containing empty object rejected", func(t *testing.T) {
		emptyPath := filepath.Join(dir, "empty.json")
		require.NoError(t, os.WriteFile(emptyPath, []byte("{}"), 0o600))
		callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id":  "C-0017",
			"report_path": emptyPath,
		})
		require.NoError(t, err)
		assert.True(t, callRes.IsError)
		assert.Contains(t, toolResultText(t, callRes), "not a Kubescape posture report JSON")
	})

	t.Run("report containing null rejected", func(t *testing.T) {
		nullPath := filepath.Join(dir, "null.json")
		require.NoError(t, os.WriteFile(nullPath, []byte("null"), 0o600))
		callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id":  "C-0017",
			"report_path": nullPath,
		})
		require.NoError(t, err)
		assert.True(t, callRes.IsError)
		assert.Contains(t, toolResultText(t, callRes), "not a Kubescape posture report JSON")
	})

	t.Run("report containing unrelated object rejected", func(t *testing.T) {
		unrelatedPath := filepath.Join(dir, "unrelated.json")
		require.NoError(t, os.WriteFile(unrelatedPath, []byte(`{"message": "hello"}`), 0o600))
		callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id":  "C-0017",
			"report_path": unrelatedPath,
		})
		require.NoError(t, err)
		assert.True(t, callRes.IsError)
		assert.Contains(t, toolResultText(t, callRes), "not a Kubescape posture report JSON")
	})

	t.Run("report containing empty results array is valid", func(t *testing.T) {
		validEmptyPath := filepath.Join(dir, "valid_empty.json")
		require.NoError(t, os.WriteFile(validEmptyPath, []byte(`{"results": []}`), 0o600))
		callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id":  "C-0017",
			"report_path": validEmptyPath,
		})
		require.NoError(t, err)
		assert.False(t, callRes.IsError, toolResultText(t, callRes))
		var resp explainControlResponse
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, callRes)), &resp))
		assert.Equal(t, "C-0017", resp.ControlID)
		require.NotNil(t, resp.FailingResources)
		assert.Empty(t, *resp.FailingResources)
	})
}

func TestExplainControl_BasePathEnforcement(t *testing.T) {
	ks := newExplainTestServer(t)
	baseDir := t.TempDir()

	resInside := remediationClusterResource("Deployment", "nginx-inside", "default")
	resInside.Source = &reporthandling.Source{
		FileType:     reporthandling.SourceTypeYaml,
		RelativePath: "inside/deploy.yaml",
	}

	resOutside := remediationClusterResource("Deployment", "nginx-outside", "default")
	resOutside.Source = &reporthandling.Source{
		FileType:     reporthandling.SourceTypeYaml,
		RelativePath: "../outside/deploy.yaml",
	}

	rule := resourcesresults.ResourceAssociatedRule{
		Name:   "immutable-container-filesystem",
		Status: apis.StatusFailed,
		Paths: []armotypes.PosturePaths{
			{FailedPath: "spec.containers[0].securityContext.readOnlyRootFilesystem"},
		},
	}
	ctrl := remediationFailedControl("C-0017", "Immutable container filesystem", rule)

	report := &reporthandlingv2.PostureReport{
		Results: []resourcesresults.Result{
			remediationClusterResult(resInside, ctrl),
			remediationClusterResult(resOutside, ctrl),
		},
		Resources: []reporthandling.Resource{*resInside, *resOutside},
	}
	reportPath := filepath.Join(baseDir, "report.json")
	reportBytes, err := json.Marshal(report)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(reportPath, reportBytes, 0o600))

	t.Run("filters out references escaping base_path and preserves inside references", func(t *testing.T) {
		callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id":  "C-0017",
			"report_path": reportPath,
			"base_path":   baseDir,
		})
		require.NoError(t, err)
		assert.False(t, callRes.IsError, toolResultText(t, callRes))

		var resp explainControlResponse
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, callRes)), &resp))

		require.NotNil(t, resp.FailingResources)
		require.Len(t, *resp.FailingResources, 1, "escaping resource must be excluded")
		assert.Equal(t, "nginx-inside", (*resp.FailingResources)[0].Name)
		assert.Equal(t, "inside/deploy.yaml", (*resp.FailingResources)[0].FilePath)
	})

	t.Run("invalid non-existent base_path", func(t *testing.T) {
		callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id":  "C-0017",
			"report_path": reportPath,
			"base_path":   filepath.Join(baseDir, "does-not-exist"),
		})
		require.NoError(t, err)
		assert.True(t, callRes.IsError)
		assert.Contains(t, toolResultText(t, callRes), "cannot be resolved")
	})

	t.Run("resolves RelativePath against recorded source root when checking base_path", func(t *testing.T) {
		outsideDir := t.TempDir()
		resWithSourceRoot := remediationClusterResource("Deployment", "nginx-source-outside", "default")
		resWithSourceRoot.Source = &reporthandling.Source{
			FileType:     reporthandling.SourceTypeYaml,
			Path:         outsideDir,
			RelativePath: "deploy.yaml",
		}
		outsideReport := &reporthandlingv2.PostureReport{
			Results: []resourcesresults.Result{
				remediationClusterResult(resWithSourceRoot, ctrl),
			},
			Resources: []reporthandling.Resource{*resWithSourceRoot},
		}
		outsideReportPath := filepath.Join(baseDir, "outside_root_report.json")
		b, err := json.Marshal(outsideReport)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(outsideReportPath, b, 0o600))

		callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id":  "C-0017",
			"report_path": outsideReportPath,
			"base_path":   baseDir,
		})
		require.NoError(t, err)
		assert.False(t, callRes.IsError, toolResultText(t, callRes))

		var resp explainControlResponse
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, callRes)), &resp))
		require.NotNil(t, resp.FailingResources)
		assert.Empty(t, *resp.FailingResources, "resource whose Source.Path is outside base_path must be excluded")
	})

	t.Run("nil raw resource does not panic with base_path", func(t *testing.T) {
		nilResResult := resourcesresults.Result{
			ResourceID: "no-raw-resource-id",
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				ctrl,
			},
		}
		nilResReport := &reporthandlingv2.PostureReport{
			Results: []resourcesresults.Result{nilResResult},
		}
		p := filepath.Join(baseDir, "nil_res_report.json")
		b, err := json.Marshal(nilResReport)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(p, b, 0o600))

		callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id":  "C-0017",
			"report_path": p,
			"base_path":   baseDir,
		})
		require.NoError(t, err)
		assert.False(t, callRes.IsError, toolResultText(t, callRes))

		var resp explainControlResponse
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, callRes)), &resp))
		require.NotNil(t, resp.FailingResources)
		require.Len(t, *resp.FailingResources, 1)
		assert.Equal(t, "no-raw-resource-id", (*resp.FailingResources)[0].ResourceID)
	})

	t.Run("source with empty paths falls back to sourcePath for base_path check", func(t *testing.T) {
		objOutside := map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]any{
				"name":      "nginx-sourcepath-outside",
				"namespace": "default",
			},
			"sourcePath": filepath.Join(t.TempDir(), "outside.yaml:1"),
		}
		resOutsideSourcePath := reporthandling.NewResource(objOutside)
		resOutsideSourcePath.ResourceID = resOutsideSourcePath.GetID()
		resOutsideSourcePath.Source = &reporthandling.Source{}

		objInside := map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]any{
				"name":      "nginx-sourcepath-inside",
				"namespace": "default",
			},
			"sourcePath": filepath.Join(baseDir, "inside.yaml:1"),
		}
		resInsideSourcePath := reporthandling.NewResource(objInside)
		resInsideSourcePath.ResourceID = resInsideSourcePath.GetID()
		resInsideSourcePath.Source = &reporthandling.Source{}

		reportObj := &reporthandlingv2.PostureReport{
			Results: []resourcesresults.Result{
				remediationClusterResult(resOutsideSourcePath, ctrl),
				remediationClusterResult(resInsideSourcePath, ctrl),
			},
			Resources: []reporthandling.Resource{*resOutsideSourcePath, *resInsideSourcePath},
		}
		p := filepath.Join(baseDir, "sourcepath_report.json")
		b, err := json.Marshal(reportObj)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(p, b, 0o600))

		callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id":  "C-0017",
			"report_path": p,
			"base_path":   baseDir,
		})
		require.NoError(t, err)
		assert.False(t, callRes.IsError, toolResultText(t, callRes))

		var resp explainControlResponse
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, callRes)), &resp))
		require.NotNil(t, resp.FailingResources)
		require.Len(t, *resp.FailingResources, 1)
		assert.Equal(t, "nginx-sourcepath-inside", (*resp.FailingResources)[0].Name)
	})

	t.Run("relative path with symlink traversal escaping base_path is excluded", func(t *testing.T) {
		outsideDir := t.TempDir()
		outsideSymlink := filepath.Join(baseDir, "symlink-outside")
		require.NoError(t, os.Symlink(outsideDir, outsideSymlink))

		resSymlinkEscape := remediationClusterResource("Deployment", "nginx-symlink-escape", "default")
		resSymlinkEscape.Source = &reporthandling.Source{
			FileType:     reporthandling.SourceTypeYaml,
			Path:         baseDir,
			RelativePath: "symlink-outside/../victim.yaml",
		}

		symlinkReport := &reporthandlingv2.PostureReport{
			Results: []resourcesresults.Result{
				remediationClusterResult(resSymlinkEscape, ctrl),
			},
			Resources: []reporthandling.Resource{*resSymlinkEscape},
		}
		p := filepath.Join(baseDir, "symlink_report.json")
		b, err := json.Marshal(symlinkReport)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(p, b, 0o600))

		callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id":  "C-0017",
			"report_path": p,
			"base_path":   baseDir,
		})
		require.NoError(t, err)
		assert.False(t, callRes.IsError, toolResultText(t, callRes))

		var resp explainControlResponse
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, callRes)), &resp))
		require.NotNil(t, resp.FailingResources)
		assert.Empty(t, *resp.FailingResources, "resource whose symlink path escapes base_path must be excluded")
	})

	t.Run("sourcePath file takes precedence over root Path when RelativePath is empty", func(t *testing.T) {
		objManifest := map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]any{
				"name":      "nginx-sourcepath-file",
				"namespace": "default",
			},
			"sourcePath": "manifests/deploy.yaml:0",
		}
		resManifest := reporthandling.NewResource(objManifest)
		resManifest.ResourceID = resManifest.GetID()
		resManifest.Source = &reporthandling.Source{
			FileType: reporthandling.SourceTypeYaml,
			Path:     baseDir,
		}

		manifestReport := &reporthandlingv2.PostureReport{
			Results: []resourcesresults.Result{
				remediationClusterResult(resManifest, ctrl),
			},
			Resources: []reporthandling.Resource{*resManifest},
		}
		p := filepath.Join(baseDir, "sourcepath_manifest_report.json")
		b, err := json.Marshal(manifestReport)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(p, b, 0o600))

		callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id":  "C-0017",
			"report_path": p,
			"base_path":   baseDir,
		})
		require.NoError(t, err)
		assert.False(t, callRes.IsError, toolResultText(t, callRes))

		var resp explainControlResponse
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, callRes)), &resp))
		require.NotNil(t, resp.FailingResources)
		require.Len(t, *resp.FailingResources, 1)
		assert.Equal(t, "manifests/deploy.yaml", (*resp.FailingResources)[0].FilePath, "file_path must name the manifest, not the root directory")
	})

	t.Run("resolves relative references against report scan root before base_path", func(t *testing.T) {
		outsideDir := t.TempDir()
		objScanRoot := map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]any{
				"name":      "nginx-scan-root",
				"namespace": "default",
			},
			"sourcePath": "deploy.yaml:0",
		}
		resScanRoot := reporthandling.NewResource(objScanRoot)
		resScanRoot.ResourceID = resScanRoot.GetID()
		resScanRoot.Source = &reporthandling.Source{
			FileType: reporthandling.SourceTypeYaml,
		}

		scanRootReport := &reporthandlingv2.PostureReport{
			Metadata: reporthandlingv2.Metadata{
				ScanMetadata: reporthandlingv2.ScanMetadata{
					ScanningTarget: reporthandlingv2.Directory,
				},
				ContextMetadata: reporthandlingv2.ContextMetadata{
					DirectoryContextMetadata: &reporthandlingv2.DirectoryContextMetadata{
						BasePath: outsideDir,
					},
				},
			},
			Results: []resourcesresults.Result{
				remediationClusterResult(resScanRoot, ctrl),
			},
			Resources: []reporthandling.Resource{*resScanRoot},
		}
		p := filepath.Join(baseDir, "scan_root_outside_report.json")
		b, err := json.Marshal(scanRootReport)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(p, b, 0o600))

		callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id":  "C-0017",
			"report_path": p,
			"base_path":   baseDir,
		})
		require.NoError(t, err)
		assert.False(t, callRes.IsError, toolResultText(t, callRes))

		var resp explainControlResponse
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, callRes)), &resp))
		require.NotNil(t, resp.FailingResources)
		assert.Empty(t, *resp.FailingResources, "resource whose scan root is outside base_path must be excluded")
	})

	t.Run("preserves relative sub-roots under base_path", func(t *testing.T) {
		subDir := filepath.Join(baseDir, "apps", "web")
		require.NoError(t, os.MkdirAll(subDir, 0o755))
		resSub := remediationClusterResource("Deployment", "nginx-sub", "default")
		resSub.Source = &reporthandling.Source{
			FileType:     reporthandling.SourceTypeYaml,
			Path:         subDir,
			RelativePath: "deploy.yaml",
		}
		subReport := &reporthandlingv2.PostureReport{
			Results: []resourcesresults.Result{
				remediationClusterResult(resSub, ctrl),
			},
			Resources: []reporthandling.Resource{*resSub},
		}
		subReportPath := filepath.Join(baseDir, "sub_report.json")
		b, err := json.Marshal(subReport)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(subReportPath, b, 0o600))

		callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id":  "C-0017",
			"report_path": subReportPath,
			"base_path":   baseDir,
		})
		require.NoError(t, err)
		assert.False(t, callRes.IsError, toolResultText(t, callRes))

		var resp explainControlResponse
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, callRes)), &resp))
		require.NotNil(t, resp.FailingResources)
		require.Len(t, *resp.FailingResources, 1)
		assert.Equal(t, filepath.Join("apps", "web", "deploy.yaml"), (*resp.FailingResources)[0].FilePath)
	})
}

func TestExplainControl_WithPathScanContext(t *testing.T) {
	ks := newExplainTestServer(t)

	res := remediationClusterResource("Deployment", "nginx", "prod")
	rule := resourcesresults.ResourceAssociatedRule{
		Name:   "immutable-container-filesystem",
		Status: apis.StatusFailed,
		Paths: []armotypes.PosturePaths{
			{
				FailedPath: "spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem",
			},
		},
	}
	ctrl := remediationFailedControl("C-0017", "Immutable container filesystem", rule)
	result := remediationClusterResult(res, ctrl)
	report := remediationClusterReport([]resourcesresults.Result{result}, res)
	reportBytes, err := json.Marshal(report)
	require.NoError(t, err)

	orig := iacScanReportFn
	t.Cleanup(func() { iacScanReportFn = orig })
	iacScanReportFn = func(_ *KubescapeMcpserver, _ context.Context, path string, controlIDs []string) (*iacScanOutcome, error) {
		assert.Equal(t, "/manifest.yaml", path)
		assert.Equal(t, []string{"C-0017"}, controlIDs)
		return &iacScanOutcome{ReportJSON: reportBytes}, nil
	}

	callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
		"control_id": "C-0017",
		"path":       "/manifest.yaml",
	})
	require.NoError(t, err)
	assert.False(t, callRes.IsError, toolResultText(t, callRes))

	var resp explainControlResponse
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, callRes)), &resp))

	assert.Equal(t, "C-0017", resp.ControlID)
	require.NotNil(t, resp.FailingResources)
	require.Len(t, *resp.FailingResources, 1)
	assert.Equal(t, "Deployment", (*resp.FailingResources)[0].Kind)
	assert.Equal(t, "nginx", (*resp.FailingResources)[0].Name)
	assert.Equal(t, "prod", (*resp.FailingResources)[0].Namespace)
	assert.Equal(t, []string{"spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem"}, (*resp.FailingResources)[0].FailedPaths)
	assert.False(t, resp.Degraded)
	assert.False(t, resp.NotEvaluated)
}

func TestExplainControl_IncompleteScanCoverage(t *testing.T) {
	ks := newExplainTestServer(t)

	report := &reporthandlingv2.PostureReport{Results: []resourcesresults.Result{}}
	reportBytes, err := json.Marshal(report)
	require.NoError(t, err)

	orig := iacScanReportFn
	t.Cleanup(func() { iacScanReportFn = orig })

	t.Run("path scan degraded with control in not evaluated controls", func(t *testing.T) {
		iacScanReportFn = func(_ *KubescapeMcpserver, _ context.Context, path string, controlIDs []string) (*iacScanOutcome, error) {
			return &iacScanOutcome{
				ReportJSON: reportBytes,
				Degraded:   true,
				NotEvaluatedControls: []cautils.NotEvaluatedControl{
					{
						ControlID: "C-0017",
						Reason:    "OPA evaluation timed out",
					},
				},
			}, nil
		}

		callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id": "C-0017",
			"path":       "/manifest.yaml",
		})
		require.NoError(t, err)
		assert.False(t, callRes.IsError, toolResultText(t, callRes))

		var resp explainControlResponse
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, callRes)), &resp))

		assert.Equal(t, "C-0017", resp.ControlID)
		assert.True(t, resp.Degraded)
		assert.True(t, resp.NotEvaluated)
		assert.Equal(t, "OPA evaluation timed out", resp.NotEvaluatedReason)
		require.NotNil(t, resp.FailingResources)
		assert.Empty(t, *resp.FailingResources)
	})

	t.Run("report scan with ScanCoverage carrying not evaluated controls", func(t *testing.T) {
		dir := t.TempDir()
		cov := &cautils.ScanCoverage{
			Degraded: true,
			NotEvaluatedControls: []cautils.NotEvaluatedControl{
				{
					ControlID: "C-0017",
					Reason:    "OPA evaluation timed out",
				},
			},
		}
		path := writeRemediationReport(t, dir, report, cov)

		callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id":  "C-0017",
			"report_path": path,
		})
		require.NoError(t, err)
		assert.False(t, callRes.IsError, toolResultText(t, callRes))

		var resp explainControlResponse
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, callRes)), &resp))

		assert.Equal(t, "C-0017", resp.ControlID)
		assert.True(t, resp.Degraded)
		assert.True(t, resp.NotEvaluated)
		assert.Equal(t, "OPA evaluation timed out", resp.NotEvaluatedReason)
	})
}

func TestExplainControl_DeleteAndReviewPathsIncluded(t *testing.T) {
	ks := newExplainTestServer(t)
	dir := t.TempDir()

	res := remediationClusterResource("Deployment", "nginx", "default")
	rule := resourcesresults.ResourceAssociatedRule{
		Name:   "host-network",
		Status: apis.StatusFailed,
		Paths: []armotypes.PosturePaths{
			{DeletePath: "spec.hostNetwork"},
			{ReviewPath: "spec.containers[0].env"},
		},
	}
	ctrl := remediationFailedControl("C-0041", "HostNetwork access", rule)
	result := remediationClusterResult(res, ctrl)
	report := remediationClusterReport([]resourcesresults.Result{result}, res)
	reportPath := writeRemediationReport(t, dir, report, nil)

	callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
		"control_id":  "C-0041",
		"report_path": reportPath,
	})
	require.NoError(t, err)
	assert.False(t, callRes.IsError, toolResultText(t, callRes))

	var resp explainControlResponse
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, callRes)), &resp))

	require.NotNil(t, resp.FailingResources)
	require.Len(t, *resp.FailingResources, 1)
	assert.Equal(t, []string{"spec.containers[0].env", "spec.hostNetwork"}, (*resp.FailingResources)[0].FailedPaths)
}

func TestExplainControl_ExceptionAware(t *testing.T) {
	ks := newExplainTestServer(t)
	dir := t.TempDir()

	res := remediationClusterResource("Deployment", "nginx", "default")
	exceptedRule := resourcesresults.ResourceAssociatedRule{
		Name:   "rule-excepted",
		Status: apis.StatusFailed,
		Paths: []armotypes.PosturePaths{
			{
				FailedPath: "spec.containers[0].securityContext.readOnlyRootFilesystem",
				FixPath:    armotypes.FixPath{Path: "spec.containers[0].securityContext.readOnlyRootFilesystem", Value: "true"},
			},
		},
		Exception: []armotypes.PostureExceptionPolicy{
			{
				PortalBase:      armotypes.PortalBase{Name: "nsa-exception"},
				Actions:         []armotypes.PostureExceptionPolicyActions{armotypes.Disable},
				PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: "C-0017"}},
			},
		},
	}
	ctrl := remediationFailedControl("C-0017", "Immutable container filesystem", exceptedRule)
	result := remediationClusterResult(res, ctrl)
	report := remediationClusterReport([]resourcesresults.Result{result}, res)

	t.Run("excepted in only scanned framework is excluded", func(t *testing.T) {
		report.SummaryDetails = cautilsSummaryWith(map[string][]string{"NSA": {"C-0017"}})
		reportPath := writeRemediationReport(t, dir, report, nil)

		callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id":  "C-0017",
			"report_path": reportPath,
		})
		require.NoError(t, err)
		assert.False(t, callRes.IsError, toolResultText(t, callRes))

		var resp explainControlResponse
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, callRes)), &resp))

		require.NotNil(t, resp.FailingResources)
		assert.Empty(t, *resp.FailingResources, "fully excepted control must have no failing resources")
	})

	t.Run("excepted in one framework but failing in another remains failing", func(t *testing.T) {
		report.SummaryDetails = cautilsSummaryWith(map[string][]string{"NSA": {"C-0017"}, "MITRE": {"C-0017"}})
		reportPath := writeRemediationReport(t, dir, report, nil)

		callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
			"control_id":  "C-0017",
			"report_path": reportPath,
		})
		require.NoError(t, err)
		assert.False(t, callRes.IsError, toolResultText(t, callRes))

		var resp explainControlResponse
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, callRes)), &resp))

		require.NotNil(t, resp.FailingResources)
		assert.Len(t, *resp.FailingResources, 1, "control still failing in MITRE must be included")
	})
}

func TestExplainScanKey_DistinctFromVerifyScanKey(t *testing.T) {
	explainKey := explainScanKey("/path/manifest.yaml", "C-0017")
	verifyKey := verifyScanKey("/path/manifest.yaml", []string{"C-0017"})

	assert.NotEqual(t, explainKey, verifyKey)
	assert.Contains(t, explainKey, "explain_control:")
	assert.Contains(t, verifyKey, "verify_remediation:")

	keyRev1 := explainScanKey("/path/manifest.yaml", "C-0017", "rev1")
	keyRev2 := explainScanKey("/path/manifest.yaml", "C-0017", "rev2")
	assert.NotEqual(t, keyRev1, keyRev2, "different revisions must yield distinct scan keys")
	assert.Equal(t, keyRev1, explainScanKey("/path/manifest.yaml", "C-0017", "rev1"), "same revision must yield identical key")
}

func TestExplainControl_InvalidFixPathNotReportedAsAutoFix(t *testing.T) {
	ks := newExplainTestServer(t)
	dir := t.TempDir()

	res := remediationClusterResource("Deployment", "nginx", "default")
	res.Source = &reporthandling.Source{
		FileType:     reporthandling.SourceTypeYaml,
		Path:         dir,
		RelativePath: "deploy.yaml",
	}
	rule := resourcesresults.ResourceAssociatedRule{
		Name:   "host-network",
		Status: apis.StatusFailed,
		Paths: []armotypes.PosturePaths{
			{
				FailedPath: "spec.hostNetwork",
				FixPath:    armotypes.FixPath{Path: "spec..hostNetwork", Value: "false"}, // invalid syntax
			},
		},
	}
	ctrl := remediationFailedControl("C-0041", "HostNetwork access", rule)
	result := remediationClusterResult(res, ctrl)
	report := remediationClusterReport([]resourcesresults.Result{result}, res)
	report.Metadata.ScanMetadata.ScanningTarget = reporthandlingv2.Directory
	report.Metadata.ContextMetadata.ClusterContextMetadata = nil
	report.Metadata.ContextMetadata.DirectoryContextMetadata = &reporthandlingv2.DirectoryContextMetadata{BasePath: dir}
	reportPath := writeRemediationReport(t, dir, report, nil)

	callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
		"control_id":  "C-0041",
		"report_path": reportPath,
	})
	require.NoError(t, err)
	assert.False(t, callRes.IsError, toolResultText(t, callRes))

	var resp explainControlResponse
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, callRes)), &resp))

	assert.False(t, resp.AutoFixAvailable, "invalid fix path must not report auto_fix_available")

	// Ensure valid syntax on the same fixture enables auto-fix, proving syntax check was the decider.
	ruleValid := resourcesresults.ResourceAssociatedRule{
		Name:   "host-network",
		Status: apis.StatusFailed,
		Paths: []armotypes.PosturePaths{
			{
				FailedPath: "spec.hostNetwork",
				FixPath:    armotypes.FixPath{Path: "spec.hostNetwork", Value: "false"},
			},
		},
	}
	ctrlValid := remediationFailedControl("C-0041", "HostNetwork access", ruleValid)
	resultValid := remediationClusterResult(res, ctrlValid)
	reportValid := remediationClusterReport([]resourcesresults.Result{resultValid}, res)
	reportValid.Metadata.ScanMetadata.ScanningTarget = reporthandlingv2.Directory
	reportValid.Metadata.ContextMetadata.ClusterContextMetadata = nil
	reportValid.Metadata.ContextMetadata.DirectoryContextMetadata = &reporthandlingv2.DirectoryContextMetadata{BasePath: dir}
	validReportPath := writeRemediationReport(t, dir, reportValid, nil)

	callResValid, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
		"control_id":  "C-0041",
		"report_path": validReportPath,
	})
	require.NoError(t, err)
	assert.False(t, callResValid.IsError, toolResultText(t, callResValid))

	var respValid explainControlResponse
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, callResValid)), &respValid))
	assert.True(t, respValid.AutoFixAvailable, "valid fix path on eligible YAML resource must report auto_fix_available")
}

func TestExplainControl_PosturePathsResourceIDFiltering(t *testing.T) {
	ks := newExplainTestServer(t)
	dir := t.TempDir()

	res := remediationClusterResource("Deployment", "nginx", "default")
	res.Source = &reporthandling.Source{
		FileType:     reporthandling.SourceTypeYaml,
		Path:         dir,
		RelativePath: "deploy.yaml",
	}
	resID := res.GetID()

	rule := resourcesresults.ResourceAssociatedRule{
		Name:   "host-network",
		Status: apis.StatusFailed,
		Paths: []armotypes.PosturePaths{
			{
				ResourceID: "other-resource-id",
				FailedPath: "spec.otherResourcePath",
				FixPath:    armotypes.FixPath{Path: "spec.hostNetwork", Value: "true"},
			},
			{
				ResourceID: resID,
				FailedPath: "spec.matchingResourcePath",
			},
		},
	}
	ctrl := remediationFailedControl("C-0041", "HostNetwork access", rule)
	result := remediationClusterResult(res, ctrl)
	report := remediationClusterReport([]resourcesresults.Result{result}, res)
	report.Metadata.ScanMetadata.ScanningTarget = reporthandlingv2.Directory
	report.Metadata.ContextMetadata.ClusterContextMetadata = nil
	report.Metadata.ContextMetadata.DirectoryContextMetadata = &reporthandlingv2.DirectoryContextMetadata{BasePath: dir}
	reportPath := writeRemediationReport(t, dir, report, nil)

	callRes, err := ks.CallTool(context.Background(), "explain_control", map[string]any{
		"control_id":  "C-0041",
		"report_path": reportPath,
	})
	require.NoError(t, err)
	assert.False(t, callRes.IsError, toolResultText(t, callRes))

	var resp explainControlResponse
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, callRes)), &resp))

	require.NotNil(t, resp.FailingResources)
	require.Len(t, *resp.FailingResources, 1)
	assert.Equal(t, []string{"spec.matchingResourcePath"}, (*resp.FailingResources)[0].FailedPaths, "paths belonging to other resources must not be attributed to this entry")
	assert.False(t, resp.AutoFixAvailable, "fix path belonging to other resource must not trigger auto_fix_available for this resource")
}
