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

func TestWorkspaceRootRejectsPathReplacedByOutsideSymlink(t *testing.T) {
	workspace := t.TempDir()
	inside := filepath.Join(workspace, "reports")
	require.NoError(t, os.Mkdir(inside, 0o700))
	report := filepath.Join(inside, "report.json")
	require.NoError(t, os.WriteFile(report, []byte(`{"results":[]}`), 0o600))
	resolved, err := pathcontainment.ResolveContainedPath(workspace, report)
	require.NoError(t, err)

	root, err := os.OpenRoot(workspace)
	require.NoError(t, err)
	defer root.Close()

	outside := t.TempDir()
	secret := filepath.Join(outside, "report.json")
	require.NoError(t, os.WriteFile(secret, []byte(outsideWorkspaceMarker), 0o600))
	require.NoError(t, os.Rename(inside, filepath.Join(workspace, "reports-original")))
	require.NoError(t, os.Symlink(outside, inside))

	_, err = readFileUnderRoot(root, resolved, 1024)
	require.Error(t, err, "a path replaced after containment must not reach the outside file")
	_, err = readRemediationReportWithRoot(resolved, root)
	require.Error(t, err, "report_path reads must use the same anchored root")
}

func TestOpenFileUnderRoot_RelativeRoot(t *testing.T) {
	origWD, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(origWD) }()

	tempDir := t.TempDir()
	require.NoError(t, os.Chdir(tempDir))

	workspace := "test-workspace"
	require.NoError(t, os.Mkdir(workspace, 0o700))
	manifest := filepath.Join(workspace, "manifest.yaml")
	require.NoError(t, os.WriteFile(manifest, []byte("kind: Pod\n"), 0o600))

	// Open root with a relative path
	root, err := os.OpenRoot(workspace)
	require.NoError(t, err)
	defer root.Close()

	// Access via relative path
	f, err := openFileUnderRoot(root, manifest)
	require.NoError(t, err, "openFileUnderRoot must succeed with relative os.Root")
	require.NoError(t, f.Close())

	// Access via absolute path
	absManifest, err := filepath.Abs(manifest)
	require.NoError(t, err)
	f, err = openFileUnderRoot(root, absManifest)
	require.NoError(t, err, "openFileUnderRoot must succeed with absolute path on relative os.Root")
	require.NoError(t, f.Close())

	// Outside file must still be rejected
	outside := filepath.Join(tempDir, "outside.yaml")
	require.NoError(t, os.WriteFile(outside, []byte("kind: Secret\n"), 0o600))
	_, err = openFileUnderRoot(root, outside)
	require.Error(t, err)
	assert.ErrorIs(t, err, pathcontainment.ErrPathEscapesWorkspace)
}

func TestOpenFileUnderRoot_SymlinkedRoot(t *testing.T) {
	tempDir := t.TempDir()
	realWorkspace := filepath.Join(tempDir, "real-workspace")
	require.NoError(t, os.Mkdir(realWorkspace, 0o700))
	manifest := filepath.Join(realWorkspace, "manifest.yaml")
	require.NoError(t, os.WriteFile(manifest, []byte("kind: Pod\n"), 0o600))

	symlinkWorkspace := filepath.Join(tempDir, "symlink-workspace")
	if err := os.Symlink(realWorkspace, symlinkWorkspace); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	root, err := os.OpenRoot(symlinkWorkspace)
	require.NoError(t, err)
	defer root.Close()

	// Path through real workspace
	f, err := openFileUnderRoot(root, manifest)
	require.NoError(t, err, "openFileUnderRoot must resolve symlinked root")
	require.NoError(t, f.Close())

	// Path through symlink workspace
	symlinkManifest := filepath.Join(symlinkWorkspace, "manifest.yaml")
	f, err = openFileUnderRoot(root, symlinkManifest)
	require.NoError(t, err, "openFileUnderRoot must resolve symlinked path under symlinked root")
	require.NoError(t, f.Close())
}

func TestOpenFileUnderRoot_RejectsReplacedWorkspaceRoot(t *testing.T) {
	tempDir := t.TempDir()
	workDir := filepath.Join(tempDir, "work")
	require.NoError(t, os.Mkdir(workDir, 0o700))

	oldReport := filepath.Join(workDir, "report.json")
	require.NoError(t, os.WriteFile(oldReport, []byte(`{"content":"old"}`), 0o600))

	root, err := os.OpenRoot(workDir)
	require.NoError(t, err)
	defer root.Close()

	oldDir := filepath.Join(tempDir, "old")
	if err := os.Rename(workDir, oldDir); err != nil {
		t.Skipf("renaming open directory not supported: %v", err)
	}

	newDir := filepath.Join(tempDir, "new")
	require.NoError(t, os.Mkdir(newDir, 0o700))
	newReport := filepath.Join(newDir, "report.json")
	require.NoError(t, os.WriteFile(newReport, []byte(`{"content":"new"}`), 0o600))

	if err := os.Symlink(newDir, workDir); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	// Canonical request for new/report.json must be rejected because root holds the old directory descriptor
	_, err = openFileUnderRoot(root, newReport)
	require.Error(t, err)
	assert.ErrorIs(t, err, pathcontainment.ErrPathEscapesWorkspace)

	// Requesting via work/report.json must also be rejected rather than opening old/report.json
	_, err = openFileUnderRoot(root, filepath.Join(workDir, "report.json"))
	require.Error(t, err)
	assert.ErrorIs(t, err, pathcontainment.ErrPathEscapesWorkspace)

	// Ensure readRemediationReportWithRoot does not silently return the old report
	_, err = readRemediationReportWithRoot(filepath.Join(workDir, "report.json"), root)
	require.Error(t, err)
}
