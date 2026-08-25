package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- fixture helpers ------------------------------------------------------
//
// Ported from core/pkg/fixhandler/unfixed_test.go, whose equivalents are
// unexported and therefore cannot be imported.

func remediationFailedRuleWithFix(path, value string) resourcesresults.ResourceAssociatedRule {
	return resourcesresults.ResourceAssociatedRule{
		Name:   "rule-" + path,
		Status: apis.StatusFailed,
		Paths: []armotypes.PosturePaths{
			{FixPath: armotypes.FixPath{Path: path, Value: value}},
		},
	}
}

// remediationFailedRuleNoFix is a failed rule carrying a FailedPath but no
// FixPath — the shape that has no deterministic fix and must surface in
// unfixed_controls rather than being silently dropped.
func remediationFailedRuleNoFix() resourcesresults.ResourceAssociatedRule {
	return resourcesresults.ResourceAssociatedRule{
		Name:   "rule-no-fix",
		Status: apis.StatusFailed,
		Paths: []armotypes.PosturePaths{
			{FailedPath: "spec.hostNetwork"},
		},
	}
}

func remediationFailedControl(id, name string, rules ...resourcesresults.ResourceAssociatedRule) resourcesresults.ResourceAssociatedControl {
	return resourcesresults.ResourceAssociatedControl{
		ControlID:               id,
		Name:                    name,
		Status:                  apis.StatusInfo{InnerStatus: apis.StatusFailed},
		ResourceAssociatedRules: rules,
	}
}

// remediationResource builds a reporthandling.Resource backed by the local YAML
// file <baseDir>/<filename>. documentIndex is encoded into sourcePath because
// that is how the fixhandler locates the document to patch.
func remediationResource(baseDir, filename, kind, name string, documentIndex int) *reporthandling.Resource {
	obj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       kind,
		"metadata": map[string]any{
			"name":      name,
			"namespace": "default",
		},
		"spec": map[string]any{},
	}
	lw := localworkload.NewLocalWorkload(obj)
	lw.SetPath(filename + ":" + strconv.Itoa(documentIndex))

	return &reporthandling.Resource{
		ResourceID: lw.GetID(),
		Object:     lw.GetObject(),
		Source:     &reporthandling.Source{FileType: reporthandling.SourceTypeYaml, Path: baseDir},
	}
}

// remediationReport wraps resources and controls into the Directory-target
// PostureReport shape NewFixHandler accepts.
func remediationReport(baseDir string, res *reporthandling.Resource, controls ...resourcesresults.ResourceAssociatedControl) *reporthandlingv2.PostureReport {
	return &reporthandlingv2.PostureReport{
		Metadata: reporthandlingv2.Metadata{
			ScanMetadata: reporthandlingv2.ScanMetadata{
				ScanningTarget: reporthandlingv2.Directory,
			},
			ContextMetadata: reporthandlingv2.ContextMetadata{
				DirectoryContextMetadata: &reporthandlingv2.DirectoryContextMetadata{
					BasePath: baseDir,
				},
			},
		},
		Results: []resourcesresults.Result{
			{
				ResourceID:         res.GetID(),
				RawResource:        res,
				AssociatedControls: controls,
			},
		},
		Resources: []reporthandling.Resource{*res},
	}
}

// stubScanReport replaces the scan seam with a canned report so the test runs
// fully offline, and restores it afterwards.
func stubScanReport(t *testing.T, report *reporthandlingv2.PostureReport) {
	t.Helper()
	orig := iacScanReportFn
	t.Cleanup(func() { iacScanReportFn = orig })
	iacScanReportFn = func(s *KubescapeMcpserver, ctx context.Context, path string, ids []string) ([]byte, error) {
		return json.Marshal(report)
	}
}

// countTempReports counts the staged report files the remediation flow creates,
// so a test can prove none were left behind.
func countTempReports(t *testing.T) int {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(os.TempDir(), "kubescape-mcp-remediation-*.json"))
	require.NoError(t, err)
	return len(matches)
}

func callApplyRemediation(t *testing.T, ksServer *KubescapeMcpserver, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := ksServer.CallTool(context.Background(), "apply_remediation", args)
	require.NoError(t, err)
	require.NotNil(t, res)
	return res
}

const deploymentNoSecurityContext = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
  namespace: default
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx
`

// --- 1. happy path --------------------------------------------------------

func TestApplyRemediation_SingleFilePatchesWithoutTouchingDisk(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "deployment.yaml")
	require.NoError(t, os.WriteFile(fixture, []byte(deploymentNoSecurityContext), 0o600))

	res := remediationResource(dir, "deployment.yaml", "Deployment", "demo", 0)
	stubScanReport(t, remediationReport(dir, res,
		remediationFailedControl("C-0013", "Non-root containers",
			remediationFailedRuleWithFix("spec.template.spec.securityContext.runAsNonRoot", "true"),
		),
	))

	before := countTempReports(t)
	ksServer := &KubescapeMcpserver{}
	result := callApplyRemediation(t, ksServer, map[string]any{
		"path":        fixture,
		"control_ids": "C-0013",
	})
	require.False(t, result.IsError, "unexpected tool error: %s", toolResultText(t, result))

	var resp remediationResponse
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &resp))

	require.Len(t, resp.Files, 1)
	assert.Equal(t, fixture, resp.Files[0].FilePath)
	assert.Contains(t, resp.Files[0].PatchedYAML, "runAsNonRoot: true")
	assert.NotEmpty(t, resp.Files[0].AppliedExpressions)
	assert.Equal(t, 1, resp.FixedControlInstances)

	// The dry-run guarantee: the file on disk is byte-identical to before.
	after, err := os.ReadFile(fixture)
	require.NoError(t, err)
	assert.Equal(t, deploymentNoSecurityContext, string(after),
		"apply_remediation must never modify the file on disk")

	assert.Equal(t, before, countTempReports(t), "staged report file was leaked")
}

// --- 2. argument validation ----------------------------------------------

func TestApplyRemediation_ArgumentValidation(t *testing.T) {
	ksServer := &KubescapeMcpserver{}

	t.Run("missing path", func(t *testing.T) {
		result := callApplyRemediation(t, ksServer, map[string]any{"control_ids": "C-0013"})
		assert.True(t, result.IsError)
		assert.Contains(t, toolResultText(t, result), "path argument is required")
	})

	t.Run("blank path", func(t *testing.T) {
		result := callApplyRemediation(t, ksServer, map[string]any{"path": "   ", "control_ids": "C-0013"})
		assert.True(t, result.IsError)
		assert.Contains(t, toolResultText(t, result), "path argument is required")
	})

	t.Run("missing control_ids", func(t *testing.T) {
		result := callApplyRemediation(t, ksServer, map[string]any{"path": "/some/path"})
		assert.True(t, result.IsError)
		assert.Contains(t, toolResultText(t, result), "control_ids")
	})
}

// --- 3. scan failure propagates ------------------------------------------

func TestApplyRemediation_ScanFailurePropagates(t *testing.T) {
	orig := iacScanReportFn
	t.Cleanup(func() { iacScanReportFn = orig })
	iacScanReportFn = func(s *KubescapeMcpserver, ctx context.Context, path string, ids []string) ([]byte, error) {
		return nil, fmt.Errorf("policy download exploded")
	}

	before := countTempReports(t)
	ksServer := &KubescapeMcpserver{}
	result := callApplyRemediation(t, ksServer, map[string]any{
		"path":        "/some/path",
		"control_ids": "C-0013",
	})

	assert.True(t, result.IsError)
	assert.Contains(t, toolResultText(t, result), "policy download exploded")
	assert.Equal(t, before, countTempReports(t), "staged report file was leaked on the error path")
}

// --- 4. nothing fixable ---------------------------------------------------

func TestApplyRemediation_NoFixableControlsReportsUnfixed(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "deployment.yaml")
	require.NoError(t, os.WriteFile(fixture, []byte(deploymentNoSecurityContext), 0o600))

	res := remediationResource(dir, "deployment.yaml", "Deployment", "demo", 0)
	stubScanReport(t, remediationReport(dir, res,
		remediationFailedControl("C-0041", "HostNetwork access", remediationFailedRuleNoFix()),
	))

	ksServer := &KubescapeMcpserver{}
	result := callApplyRemediation(t, ksServer, map[string]any{
		"path":        fixture,
		"control_ids": "C-0041",
	})
	require.False(t, result.IsError, "a control with no auto-fix must not be an error: %s", toolResultText(t, result))

	var resp remediationResponse
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &resp))

	assert.Empty(t, resp.Files, "nothing was fixable, so no patched files")
	assert.Equal(t, 0, resp.FixedControlInstances)
	require.NotEmpty(t, resp.UnfixedControls, "the agent must be told which controls it may not guess at")
	assert.Equal(t, "C-0041", resp.UnfixedControls[0].ControlID)
	assert.NotEmpty(t, resp.UnfixedControls[0].Reason)
}

// --- 5. multi-document file ----------------------------------------------

const twoDocumentDeployments = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: first
  namespace: default
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: second
  namespace: default
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx
`

func TestApplyRemediation_MultiDocumentPatchesOnlyTargetDocument(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "deployments.yaml")
	require.NoError(t, os.WriteFile(fixture, []byte(twoDocumentDeployments), 0o600))

	// documentIndex 1 -> the fix expression is scoped with select(di==1).
	res := remediationResource(dir, "deployments.yaml", "Deployment", "second", 1)
	stubScanReport(t, remediationReport(dir, res,
		remediationFailedControl("C-0013", "Non-root containers",
			remediationFailedRuleWithFix("spec.template.spec.securityContext.runAsNonRoot", "true"),
		),
	))

	ksServer := &KubescapeMcpserver{}
	result := callApplyRemediation(t, ksServer, map[string]any{
		"path":        fixture,
		"control_ids": "C-0013",
	})
	require.False(t, result.IsError, "unexpected tool error: %s", toolResultText(t, result))

	var resp remediationResponse
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &resp))
	require.Len(t, resp.Files, 1)

	patched := resp.Files[0].PatchedYAML
	assert.Equal(t, 1, strings.Count(patched, "runAsNonRoot: true"),
		"exactly one document may be patched")

	docs := strings.Split(patched, "\n---")
	require.Len(t, docs, 2, "both documents must survive the patch")
	assert.NotContains(t, docs[0], "runAsNonRoot", "document 0 must be untouched")
	assert.Contains(t, docs[1], "runAsNonRoot: true", "document 1 is the target")
}

// --- 6. tool registration -------------------------------------------------

func TestCreateRemediationTools_RegistersApplyRemediation(t *testing.T) {
	ksServer := &KubescapeMcpserver{s: server.NewMCPServer("kubescape-test", "test")}
	require.NotPanics(t, func() { createRemediationTools(ksServer) })

	message, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
	})
	require.NoError(t, err)
	raw, err := json.Marshal(ksServer.s.HandleMessage(context.Background(), message))
	require.NoError(t, err)

	var listed struct {
		Result struct {
			Tools []struct {
				Name        string `json:"name"`
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
		if tool.Name != "apply_remediation" {
			continue
		}
		found = true
		assert.Contains(t, tool.InputSchema.Properties, "path")
		assert.Contains(t, tool.InputSchema.Properties, "control_ids")
		assert.Contains(t, tool.InputSchema.Required, "path")
		assert.Contains(t, tool.InputSchema.Required, "control_ids")
	}
	assert.True(t, found, "apply_remediation was not registered")
}
