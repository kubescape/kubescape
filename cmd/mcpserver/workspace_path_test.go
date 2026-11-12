package mcpserver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/pkg/pathcontainment"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The manifest the fixtures place outside the workspace carries this marker,
// so a test can tell whether any of its content was returned.
const outsideWorkspaceMarker = "outside-workspace-marker"

func newWorkspaceTestDir(t *testing.T) string {
	t.Helper()
	workspace, err := pathcontainment.ResolveBaseDir(t.TempDir())
	require.NoError(t, err)
	return workspace
}

// writeFileReportIn writes a file-scan report for one Deployment manifest:
// the manifest goes in manifestDir and the report in reportDir.
func writeFileReportIn(t *testing.T, manifestDir, reportDir string) string {
	t.Helper()
	manifest := deploymentNoSecurityContext + "# " + outsideWorkspaceMarker + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(manifestDir, "deploy.yaml"), []byte(manifest), 0o600))
	res := remediationResource(manifestDir, "deploy.yaml", "Deployment", "demo", 0)
	report := remediationReport(manifestDir, res,
		remediationFailedControl("C-0057", "Privileged container",
			remediationFailedRuleWithFix(privilegedFixPath, "false")),
	)
	return writeRemediationReport(t, reportDir, report, nil)
}

func requireWorkspaceRejection(t *testing.T, resultText string, isError bool, argument string) {
	t.Helper()
	require.True(t, isError, "a path outside --workspace must be rejected, got: %s", resultText)
	var te ToolError
	require.NoError(t, json.Unmarshal([]byte(resultText), &te))
	assert.Equal(t, ErrCodeInvalidArgument, te.Code)
	assert.Equal(t, argument, te.Details["argument"])
	assert.Contains(t, te.Message, "outside baseDir")
	assert.NotContains(t, resultText, outsideWorkspaceMarker, "no content of the outside file may be returned")
}

// apply_remediation with report_path reads the report and then the files it
// names under base_path, and returns those files patched. With --workspace set,
// path is confined to the workspace; report_path and base_path must be too, or
// any file the server can read is returned to the client.
func TestApplyRemediation_ReportPathsConfinedToWorkspace(t *testing.T) {
	forbidScan(t)
	workspace := newWorkspaceTestDir(t)
	outside := t.TempDir()
	srv := &KubescapeMcpserver{workspaceDir: workspace}

	t.Run("base_path outside the workspace", func(t *testing.T) {
		reportPath := writeFileReportIn(t, outside, workspace)
		res := callApplyRemediation(t, srv, map[string]any{"report_path": reportPath, "base_path": outside, "control_ids": "C-0057"})
		requireWorkspaceRejection(t, toolResultText(t, res), res.IsError, "base_path")
	})

	t.Run("report_path outside the workspace", func(t *testing.T) {
		manifests := t.TempDir()
		reportPath := writeFileReportIn(t, manifests, outside)
		res := callApplyRemediation(t, srv, map[string]any{"report_path": reportPath, "base_path": workspace, "control_ids": "C-0057"})
		requireWorkspaceRejection(t, toolResultText(t, res), res.IsError, "report_path")
	})

	t.Run("base_path escaping through a symlink in the workspace", func(t *testing.T) {
		reportPath := writeFileReportIn(t, outside, workspace)
		link := filepath.Join(workspace, "escape")
		require.NoError(t, os.Symlink(outside, link))
		res := callApplyRemediation(t, srv, map[string]any{"report_path": reportPath, "base_path": link, "control_ids": "C-0057"})
		requireWorkspaceRejection(t, toolResultText(t, res), res.IsError, "base_path")
	})

	t.Run("base_path escaping through a relative traversal", func(t *testing.T) {
		reportPath := writeFileReportIn(t, outside, workspace)
		rel, err := filepath.Rel(workspace, outside)
		require.NoError(t, err)
		res := callApplyRemediation(t, srv, map[string]any{"report_path": reportPath, "base_path": rel, "control_ids": "C-0057"})
		requireWorkspaceRejection(t, toolResultText(t, res), res.IsError, "base_path")
	})
}

// Confinement must not break the supported use: a report and its files inside
// the workspace, given absolutely or relative to the workspace.
func TestApplyRemediation_ReportPathsInsideWorkspaceStillWork(t *testing.T) {
	forbidScan(t)
	workspace := newWorkspaceTestDir(t)
	manifests := filepath.Join(workspace, "manifests")
	require.NoError(t, os.Mkdir(manifests, 0o700))
	reportPath := writeFileReportIn(t, manifests, workspace)
	srv := &KubescapeMcpserver{workspaceDir: workspace}

	for name, args := range map[string]map[string]any{
		"absolute": {"report_path": reportPath, "base_path": manifests},
		"relative": {"report_path": "report.json", "base_path": "manifests"},
	} {
		t.Run(name, func(t *testing.T) {
			args["control_ids"] = "C-0057"
			res := callApplyRemediation(t, srv, args)
			require.False(t, res.IsError, "unexpected error: %s", toolResultText(t, res))
			var resp remediationResponse
			require.NoError(t, json.Unmarshal([]byte(toolResultText(t, res)), &resp))
			require.Len(t, resp.Files, 1)
			assert.Contains(t, resp.Files[0].PatchedYAML, "privileged: false")
		})
	}
}

// Without --workspace the server is unconstrained by design, and report_path
// keeps reading wherever it points.
func TestApplyRemediation_ReportPathsUnconstrainedWithoutWorkspace(t *testing.T) {
	forbidScan(t)
	outside := t.TempDir()
	reportPath := writeFileReportIn(t, outside, t.TempDir())

	res := callApplyRemediation(t, &KubescapeMcpserver{}, map[string]any{"report_path": reportPath, "base_path": outside, "control_ids": "C-0057"})
	require.False(t, res.IsError, "unexpected error: %s", toolResultText(t, res))
}

func TestDiffReports_ReportsConfinedToWorkspace(t *testing.T) {
	workspace := newWorkspaceTestDir(t)
	ksServer := newDiffReportsTestServer(t)
	ksServer.workspaceDir = workspace

	inside := func(name, content string) string {
		path := filepath.Join(workspace, name)
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		return path
	}
	base := inside("base.json", diffReportsPostureBase)
	head := inside("head.json", diffReportsPostureHead)
	outsideBase := writeDiffReportFixture(t, diffReportsPostureBase)
	outsideHead := writeDiffReportFixture(t, diffReportsPostureHead)

	for _, tc := range []struct {
		name, base, head, argument string
	}{
		{"base_report outside", outsideBase, head, "base_report"},
		{"head_report outside", base, outsideHead, "head_report"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "diff_reports", map[string]any{
				"base_report": tc.base,
				"head_report": tc.head,
			}))
			te := parsePSSToolError(t, result)
			assert.Equal(t, ErrCodeInvalidArgument, te.Code)
			assert.Equal(t, tc.argument, te.Details["argument"])
			assert.Contains(t, te.Message, "outside baseDir")
		})
	}

	t.Run("both inside", func(t *testing.T) {
		result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "diff_reports", map[string]any{
			"base_report": "base.json",
			"head_report": head,
		}))
		require.False(t, result.IsError, "unexpected error: %s", toolResultText(t, result))
		structured, ok := result.StructuredContent.(diffReportsResult)
		require.True(t, ok)
		assert.Equal(t, "posture", structured.Kind)
		assert.Equal(t, "base.json", structured.BaseReport, "the result echoes the path as the caller gave it")
	})
}
