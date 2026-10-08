package mcpserver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	diffReportsPostureBase = `{"results":[],"summaryDetails":{"controls":{}}}`
	diffReportsPostureHead = `{
		"results":[{"resourceID":"res1","controls":[
			{"controlID":"C-HIGH","name":"High","status":{"status":"failed"}}
		]}],
		"summaryDetails":{"controls":{"C-HIGH":{"scoreFactor":7.0}}}
	}`
	diffReportsImageBase = `{"matches":[
		{"vulnerability":{"id":"CVE-OLD","severity":"High","fix":{"versions":[]}},"artifact":{"name":"openssl","version":"3.0.1","type":"apk"}}
	],"source":{"target":{"userInput":"app:1.0"}}}`
	diffReportsImageHead = `{"matches":[
		{"vulnerability":{"id":"CVE-NEW-HIGH","severity":"High","fix":{"versions":["2.0"]}},"artifact":{"name":"curl","version":"1.0","type":"apk"}}
	],"source":{"target":{"userInput":"app:1.1"}}}`
)

func newDiffReportsTestServer(t *testing.T) *KubescapeMcpserver {
	t.Helper()
	ksServer := &KubescapeMcpserver{
		s: server.NewMCPServer(
			"kubescape-test",
			"test",
			server.WithToolCapabilities(false),
			server.WithRecovery(),
		),
	}
	createDiffReportsTools(ksServer)
	return ksServer
}

func writeDiffReportFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestDiffReports_PostureComparison(t *testing.T) {
	ksServer := newDiffReportsTestServer(t)
	base := writeDiffReportFixture(t, diffReportsPostureBase)
	head := writeDiffReportFixture(t, diffReportsPostureHead)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "diff_reports", map[string]any{
		"base_report": base,
		"head_report": head,
	}))
	require.False(t, result.IsError, "unexpected tool error: %s", toolResultText(t, result))

	var parsed diffReportsResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))

	assert.Equal(t, "posture", parsed.Kind)
	assert.Equal(t, base, parsed.BaseReport)
	assert.Equal(t, head, parsed.HeadReport)
	assert.Nil(t, parsed.Vulnerability)
	require.NotNil(t, parsed.Posture)
	require.Len(t, parsed.Posture.New, 1)
	assert.Equal(t, "C-HIGH", parsed.Posture.New[0].ControlID)

	require.NotNil(t, result.StructuredContent)
	structured, ok := result.StructuredContent.(diffReportsResult)
	require.True(t, ok, "StructuredContent must be a diffReportsResult, got %T", result.StructuredContent)
	assert.Equal(t, "posture", structured.Kind)
	require.NotNil(t, structured.Posture)
	assert.Equal(t, parsed.Posture, structured.Posture)
}

func TestDiffReports_VulnerabilityComparison(t *testing.T) {
	ksServer := newDiffReportsTestServer(t)
	base := writeDiffReportFixture(t, diffReportsImageBase)
	head := writeDiffReportFixture(t, diffReportsImageHead)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "diff_reports", map[string]any{
		"base_report": base,
		"head_report": head,
	}))
	require.False(t, result.IsError, "unexpected tool error: %s", toolResultText(t, result))

	var parsed diffReportsResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))

	assert.Equal(t, "vulnerability", parsed.Kind)
	assert.Nil(t, parsed.Posture)
	require.NotNil(t, parsed.Vulnerability)
	require.Len(t, parsed.Vulnerability.New, 1)
	assert.Equal(t, "CVE-NEW-HIGH", parsed.Vulnerability.New[0].ID)
	require.Len(t, parsed.Vulnerability.Resolved, 1)
	assert.Equal(t, "CVE-OLD", parsed.Vulnerability.Resolved[0].ID)

	require.NotNil(t, result.StructuredContent)
	structured, ok := result.StructuredContent.(diffReportsResult)
	require.True(t, ok, "StructuredContent must be a diffReportsResult, got %T", result.StructuredContent)
	assert.Equal(t, "vulnerability", structured.Kind)
	require.NotNil(t, structured.Vulnerability)
	require.Len(t, structured.Vulnerability.New, 1)
	assert.Equal(t, "CVE-NEW-HIGH", structured.Vulnerability.New[0].ID)
	require.Len(t, structured.Vulnerability.Resolved, 1)
	assert.Equal(t, "CVE-OLD", structured.Vulnerability.Resolved[0].ID)
}

func TestDiffReports_MissingReportPathReturnsInvalidArgument(t *testing.T) {
	ksServer := newDiffReportsTestServer(t)
	head := writeDiffReportFixture(t, diffReportsPostureHead)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "diff_reports", map[string]any{
		"base_report": filepath.Join(t.TempDir(), "missing.json"),
		"head_report": head,
	}))
	te := parsePSSToolError(t, result)
	assert.Equal(t, ErrCodeInvalidArgument, te.Code)
}

func TestDiffReports_MixedReportKindsReturnsInvalidArgument(t *testing.T) {
	ksServer := newDiffReportsTestServer(t)
	base := writeDiffReportFixture(t, diffReportsPostureBase)
	head := writeDiffReportFixture(t, diffReportsImageHead)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "diff_reports", map[string]any{
		"base_report": base,
		"head_report": head,
	}))
	te := parsePSSToolError(t, result)
	assert.Equal(t, ErrCodeInvalidArgument, te.Code)
	assert.Contains(t, te.Message, "cannot compare an image vulnerability report with a posture report")
	assert.Equal(t, "posture", te.Details["base_report_kind"])
	assert.Equal(t, "vulnerability", te.Details["head_report_kind"])
}

func TestDiffReports_MissingArgumentsReturnInvalidArgument(t *testing.T) {
	ksServer := newDiffReportsTestServer(t)
	head := writeDiffReportFixture(t, diffReportsPostureHead)

	t.Run("missing base_report", func(t *testing.T) {
		result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "diff_reports", map[string]any{
			"head_report": head,
		}))
		te := parsePSSToolError(t, result)
		assert.Equal(t, ErrCodeInvalidArgument, te.Code)
		assert.Equal(t, "base_report", te.Details["argument"])
	})

	t.Run("missing head_report", func(t *testing.T) {
		result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "diff_reports", map[string]any{
			"base_report": head,
		}))
		te := parsePSSToolError(t, result)
		assert.Equal(t, ErrCodeInvalidArgument, te.Code)
		assert.Equal(t, "head_report", te.Details["argument"])
	})

	t.Run("no arguments at all", func(t *testing.T) {
		result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "diff_reports", map[string]any{}))
		te := parsePSSToolError(t, result)
		assert.Equal(t, ErrCodeInvalidArgument, te.Code)
	})
}
