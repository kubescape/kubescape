package mcpserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	verifyResA = "path=111/api=apps/v1/default/Deployment/a"
	verifyResB = "path=222/api=apps/v1/default/Deployment/b"
)

func verifyControl(id string, status apis.ScanningStatus, sub apis.ScanningSubStatus) resourcesresults.ResourceAssociatedControl {
	return resourcesresults.ResourceAssociatedControl{
		ControlID: id,
		Status:    apis.StatusInfo{InnerStatus: status, SubStatus: sub},
	}
}

func verifyResourceResult(resourceID string, controls ...resourcesresults.ResourceAssociatedControl) resourcesresults.Result {
	return resourcesresults.Result{ResourceID: resourceID, AssociatedControls: controls}
}

// cleanCoverage is the coverage of a complete scan.
func cleanCoverage() *cautils.ScanCoverage {
	return &cautils.ScanCoverage{EvaluatedControls: 1, TotalControls: 1}
}

// verifyOutcome builds the scan outcome the verifier consumes: the report with
// its top-level scanCoverage, as runIaCScanControlsReport writes it.
func verifyOutcome(t *testing.T, results []resourcesresults.Result, coverage *cautils.ScanCoverage, degraded bool) *iacScanOutcome {
	t.Helper()
	envelope := struct {
		*reporthandlingv2.PostureReport
		ScanCoverage *cautils.ScanCoverage `json:"scanCoverage,omitempty"`
	}{
		PostureReport: &reporthandlingv2.PostureReport{Results: results},
		ScanCoverage:  coverage,
	}
	raw, err := json.Marshal(&envelope)
	require.NoError(t, err)
	return &iacScanOutcome{ReportJSON: raw, Degraded: degraded}
}

// verifyArgItem builds an apply_remediation-shaped item as a decoded JSON
// value, the way it arrives in the tool's arguments.
func verifyArgItem(resourceID, controlID string) map[string]any {
	return map[string]any{
		"resource_id":    resourceID,
		"control":        map[string]any{"id": controlID, "name": "ignored"},
		"classification": "patch_available",
		"evidence":       []any{},
		"file_path":      "/ignored/file.yaml",
	}
}

func callVerifyRemediation(t *testing.T, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := (&KubescapeMcpserver{}).CallTool(context.Background(), "verify_remediation", args)
	require.NoError(t, err)
	require.NotNil(t, res)
	return res
}

func decodeVerifyResponse(t *testing.T, result *mcp.CallToolResult) verifyResponse {
	t.Helper()
	require.False(t, result.IsError, "unexpected tool error: %s", toolResultText(t, result))
	var resp verifyResponse
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &resp))
	return resp
}

func TestVerifyRemediation_Verdicts(t *testing.T) {
	passed := func(id string) resourcesresults.ResourceAssociatedControl {
		return verifyControl(id, apis.StatusPassed, apis.SubStatusUnknown)
	}
	failed := func(id string) resourcesresults.ResourceAssociatedControl {
		return verifyControl(id, apis.StatusFailed, apis.SubStatusUnknown)
	}

	tests := []struct {
		name     string
		results  []resourcesresults.Result
		coverage *cautils.ScanCoverage
		degraded bool
		resource string
		control  string
		verdict  string
		reason   string
		wantFlag bool
	}{
		{
			name:     "passed with no sub-status and complete coverage is resolved",
			results:  []resourcesresults.Result{verifyResourceResult(verifyResA, passed("C-0017"))},
			coverage: cleanCoverage(), resource: verifyResA, control: "C-0017",
			verdict: verdictResolved, reason: reasonControlPassed,
		},
		{
			name:     "control id matching ignores case and padding",
			results:  []resourcesresults.Result{verifyResourceResult(verifyResA, passed("C-0017"))},
			coverage: cleanCoverage(), resource: verifyResA, control: " c-0017 ",
			verdict: verdictResolved, reason: reasonControlPassed,
		},
		{
			name:     "failed control is still failing",
			results:  []resourcesresults.Result{verifyResourceResult(verifyResA, failed("C-0017"))},
			coverage: cleanCoverage(), resource: verifyResA, control: "C-0017",
			verdict: verdictStillFailing, reason: reasonControlFailed,
		},
		{
			name:     "failed control stays still failing on a degraded scan",
			results:  []resourcesresults.Result{verifyResourceResult(verifyResA, failed("C-0017"))},
			coverage: cleanCoverage(), degraded: true, resource: verifyResA, control: "C-0017",
			verdict: verdictStillFailing, reason: reasonControlFailed, wantFlag: true,
		},
		{
			name:     "missing resource is unverified, never resolved",
			results:  []resourcesresults.Result{verifyResourceResult(verifyResB, passed("C-0017"))},
			coverage: cleanCoverage(), resource: verifyResA, control: "C-0017",
			verdict: verdictUnverified, reason: reasonResourceNotFound,
		},
		{
			name:     "empty report is unverified, never resolved",
			results:  nil,
			coverage: cleanCoverage(), resource: verifyResA, control: "C-0017",
			verdict: verdictUnverified, reason: reasonResourceNotFound,
		},
		{
			name:     "item without resource id is unverified",
			results:  []resourcesresults.Result{verifyResourceResult(verifyResA, passed("C-0017"))},
			coverage: cleanCoverage(), resource: "", control: "C-0017",
			verdict: verdictUnverified, reason: reasonResourceIDMissing,
		},
		{
			name:     "missing control is unverified, never resolved",
			results:  []resourcesresults.Result{verifyResourceResult(verifyResA, passed("C-0057"))},
			coverage: cleanCoverage(), resource: verifyResA, control: "C-0017",
			verdict: verdictUnverified, reason: reasonControlNotFound,
		},
		{
			name:     "resource with no controls is unverified",
			results:  []resourcesresults.Result{verifyResourceResult(verifyResA)},
			coverage: cleanCoverage(), resource: verifyResA, control: "C-0017",
			verdict: verdictUnverified, reason: reasonControlNotFound,
		},
		{
			name:     "skipped control is unverified",
			results:  []resourcesresults.Result{verifyResourceResult(verifyResA, verifyControl("C-0017", apis.StatusSkipped, apis.SubStatusUnknown))},
			coverage: cleanCoverage(), resource: verifyResA, control: "C-0017",
			verdict: verdictUnverified, reason: reasonControlNotEvaluated,
		},
		{
			name:     "passed with notEvaluated sub-status is unverified",
			results:  []resourcesresults.Result{verifyResourceResult(verifyResA, verifyControl("C-0017", apis.StatusPassed, apis.SubStatusNotEvaluated))},
			coverage: cleanCoverage(), resource: verifyResA, control: "C-0017",
			verdict: verdictUnverified, reason: reasonControlNotEvaluated,
		},
		{
			name:     "passed with incompleteCoverage sub-status is unverified",
			results:  []resourcesresults.Result{verifyResourceResult(verifyResA, verifyControl("C-0017", apis.StatusPassed, apis.SubStatusIncompleteCoverage))},
			coverage: cleanCoverage(), resource: verifyResA, control: "C-0017",
			verdict: verdictUnverified, reason: reasonControlNotEvaluated,
		},
		{
			name:     "passed with an exception sub-status is not resolved",
			results:  []resourcesresults.Result{verifyResourceResult(verifyResA, verifyControl("C-0017", apis.StatusPassed, apis.SubStatusException))},
			coverage: cleanCoverage(), resource: verifyResA, control: "C-0017",
			verdict: verdictUnverified, reason: reasonControlSubStatus,
		},
		{
			name:     "passed with an irrelevant sub-status is not resolved",
			results:  []resourcesresults.Result{verifyResourceResult(verifyResA, verifyControl("C-0017", apis.StatusPassed, apis.SubStatusIrrelevant))},
			coverage: cleanCoverage(), resource: verifyResA, control: "C-0017",
			verdict: verdictUnverified, reason: reasonControlSubStatus,
		},
		{
			name:     "unknown status is not treated as success",
			results:  []resourcesresults.Result{verifyResourceResult(verifyResA, verifyControl("C-0017", apis.ScanningStatus("mystery"), apis.SubStatusUnknown))},
			coverage: cleanCoverage(), resource: verifyResA, control: "C-0017",
			verdict: verdictUnverified, reason: reasonControlStatusUnknown,
		},
		{
			name:     "control listed as not evaluated is unverified even if the report says passed",
			results:  []resourcesresults.Result{verifyResourceResult(verifyResA, passed("C-0017"))},
			coverage: &cautils.ScanCoverage{NotEvaluatedControls: []cautils.NotEvaluatedControl{{ControlID: "c-0017", Reason: "timeout"}}, Degraded: true},
			resource: verifyResA, control: "C-0017",
			verdict: verdictUnverified, reason: reasonControlNotEvaluated, wantFlag: true,
		},
		{
			name:     "control listed as not evaluated is not reported as still failing",
			results:  []resourcesresults.Result{verifyResourceResult(verifyResA, failed("C-0017"))},
			coverage: &cautils.ScanCoverage{NotEvaluatedControls: []cautils.NotEvaluatedControl{{ControlID: "C-0017"}}, Degraded: true},
			resource: verifyResA, control: "C-0017",
			verdict: verdictUnverified, reason: reasonControlNotEvaluated, wantFlag: true,
		},
		{
			name:     "degraded coverage flag blocks resolved",
			results:  []resourcesresults.Result{verifyResourceResult(verifyResA, passed("C-0017"))},
			coverage: &cautils.ScanCoverage{Degraded: true}, resource: verifyResA, control: "C-0017",
			verdict: verdictUnverified, reason: reasonCoverageInsufficient, wantFlag: true,
		},
		{
			name:     "degraded scan outcome blocks resolved even with clean coverage",
			results:  []resourcesresults.Result{verifyResourceResult(verifyResA, passed("C-0017"))},
			coverage: cleanCoverage(), degraded: true, resource: verifyResA, control: "C-0017",
			verdict: verdictUnverified, reason: reasonCoverageInsufficient, wantFlag: true,
		},
		{
			name:     "missing scanCoverage blocks resolved",
			results:  []resourcesresults.Result{verifyResourceResult(verifyResA, passed("C-0017"))},
			coverage: nil, resource: verifyResA, control: "C-0017",
			verdict: verdictUnverified, reason: reasonCoverageInsufficient, wantFlag: true,
		},
		{
			name:    "skipped manifests block resolved",
			results: []resourcesresults.Result{verifyResourceResult(verifyResA, passed("C-0017"))},
			coverage: &cautils.ScanCoverage{SkippedManifests: []cautils.SkippedManifest{{
				Path: "broken.yaml", Reason: "invalid YAML",
			}}},
			resource: verifyResA, control: "C-0017",
			verdict: verdictUnverified, reason: reasonCoverageInsufficient, wantFlag: true,
		},
		{
			name:     "failed GVR pulls block resolved",
			results:  []resourcesresults.Result{verifyResourceResult(verifyResA, passed("C-0017"))},
			coverage: &cautils.ScanCoverage{FailedGVRPulls: []cautils.FailedGVRPull{{GVR: "apps/v1/deployments"}}},
			resource: verifyResA, control: "C-0017",
			verdict: verdictUnverified, reason: reasonCoverageInsufficient, wantFlag: true,
		},
		{
			name:     "partial GVR pulls block resolved",
			results:  []resourcesresults.Result{verifyResourceResult(verifyResA, passed("C-0017"))},
			coverage: &cautils.ScanCoverage{PartialGVRPulls: []cautils.PartialGVRPull{{GVR: "apps/v1/deployments"}}},
			resource: verifyResA, control: "C-0017",
			verdict: verdictUnverified, reason: reasonCoverageInsufficient, wantFlag: true,
		},
		{
			name:     "policy degradations block resolved",
			results:  []resourcesresults.Result{verifyResourceResult(verifyResA, passed("C-0017"))},
			coverage: &cautils.ScanCoverage{PolicyDegradations: []cautils.PolicyDegradation{{Component: "exceptions"}}},
			resource: verifyResA, control: "C-0017",
			verdict: verdictUnverified, reason: reasonCoverageInsufficient, wantFlag: true,
		},
		{
			name: "the same resource id reported twice is ambiguous even if both pass",
			results: []resourcesresults.Result{
				verifyResourceResult(verifyResA, passed("C-0017")),
				verifyResourceResult(verifyResA, passed("C-0017")),
			},
			coverage: cleanCoverage(), resource: verifyResA, control: "C-0017",
			verdict: verdictUnverified, reason: reasonAmbiguousResource,
		},
		{
			name: "the same control reported twice on a resource is ambiguous even if both pass",
			results: []resourcesresults.Result{
				verifyResourceResult(verifyResA, passed("C-0017"), passed("C-0017")),
			},
			coverage: cleanCoverage(), resource: verifyResA, control: "C-0017",
			verdict: verdictUnverified, reason: reasonAmbiguousControl,
		},
		{
			name: "a pass next to a failure of the same control is ambiguous, not resolved",
			results: []resourcesresults.Result{
				verifyResourceResult(verifyResA, passed("C-0017"), failed("C-0017")),
			},
			coverage: cleanCoverage(), resource: verifyResA, control: "C-0017",
			verdict: verdictUnverified, reason: reasonAmbiguousControl,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stubScanOutcome(t, verifyOutcome(t, tc.results, tc.coverage, tc.degraded))
			resp := decodeVerifyResponse(t, callVerifyRemediation(t, map[string]any{
				"path":  "/some/path",
				"items": []any{verifyArgItem(tc.resource, tc.control)},
			}))
			require.Len(t, resp.Results, 1)
			got := resp.Results[0]
			assert.Equal(t, tc.verdict, got.Verdict)
			assert.Equal(t, tc.reason, got.Reason)
			assert.Equal(t, tc.resource, got.ResourceID)
			if tc.verdict == verdictUnverified {
				assert.NotEmpty(t, got.Message)
			} else {
				assert.Empty(t, got.Message)
			}
			if tc.wantFlag {
				assert.True(t, resp.Degraded, "a scan with a coverage gap must be flagged")
			}
			if tc.verdict == verdictResolved {
				assert.False(t, resp.Degraded)
			}
		})
	}
}

func TestVerifyRemediation_MultipleItemsKeepInputOrder(t *testing.T) {
	stubScanOutcome(t, verifyOutcome(t, []resourcesresults.Result{
		verifyResourceResult(verifyResA,
			verifyControl("C-0017", apis.StatusPassed, apis.SubStatusUnknown),
			verifyControl("C-0057", apis.StatusFailed, apis.SubStatusUnknown),
		),
		verifyResourceResult(verifyResB, verifyControl("C-0017", apis.StatusFailed, apis.SubStatusUnknown)),
	}, cleanCoverage(), false))

	resp := decodeVerifyResponse(t, callVerifyRemediation(t, map[string]any{
		"path": "/some/path",
		"items": []any{
			verifyArgItem(verifyResB, "C-0017"),
			verifyArgItem(verifyResA, "C-0057"),
			verifyArgItem("path=999/api=apps/v1/default/Deployment/gone", "C-0017"),
			verifyArgItem(verifyResA, "C-0017"),
			verifyArgItem(verifyResA, "C-0017"), // a repeated item gets its own result
		},
	}))

	want := []struct {
		resource, control, verdict string
	}{
		{verifyResB, "C-0017", verdictStillFailing},
		{verifyResA, "C-0057", verdictStillFailing},
		{"path=999/api=apps/v1/default/Deployment/gone", "C-0017", verdictUnverified},
		{verifyResA, "C-0017", verdictResolved},
		{verifyResA, "C-0017", verdictResolved},
	}
	require.Len(t, resp.Results, len(want))
	for i, w := range want {
		assert.Equal(t, i, resp.Results[i].Index)
		assert.Equal(t, w.resource, resp.Results[i].ResourceID, "item %d", i)
		assert.Equal(t, w.control, resp.Results[i].ControlID, "item %d", i)
		assert.Equal(t, w.verdict, resp.Results[i].Verdict, "item %d", i)
	}
	assert.Equal(t, verifySummary{Resolved: 2, StillFailing: 2, Unverified: 1}, resp.Summary)
}

func TestVerifyRemediation_ScansOnceForTheDistinctControls(t *testing.T) {
	orig := iacScanReportFn
	t.Cleanup(func() { iacScanReportFn = orig })
	var calls int
	var gotPath string
	var gotIDs []string
	outcome := verifyOutcome(t, []resourcesresults.Result{verifyResourceResult(verifyResA,
		verifyControl("C-0017", apis.StatusPassed, apis.SubStatusUnknown))}, cleanCoverage(), false)
	iacScanReportFn = func(s *KubescapeMcpserver, ctx context.Context, path string, ids []string) (*iacScanOutcome, error) {
		calls++
		gotPath, gotIDs = path, ids
		return outcome, nil
	}

	decodeVerifyResponse(t, callVerifyRemediation(t, map[string]any{
		"path": "  /some/path ",
		"items": []any{
			verifyArgItem(verifyResA, "c-0057"),
			verifyArgItem(verifyResA, "C-0017"),
			verifyArgItem(verifyResB, "C-0017"),
			verifyArgItem(verifyResB, "C-0057"),
		},
	}))

	assert.Equal(t, 1, calls, "one scan must serve every item")
	assert.Equal(t, "/some/path", gotPath)
	assert.Equal(t, []string{"C-0017", "C-0057"}, gotIDs)
}

func TestVerifyRemediation_EmptyItemsDoNotScan(t *testing.T) {
	orig := iacScanReportFn
	t.Cleanup(func() { iacScanReportFn = orig })
	iacScanReportFn = func(*KubescapeMcpserver, context.Context, string, []string) (*iacScanOutcome, error) {
		t.Fatal("scan must not run when there is nothing to verify")
		return nil, nil
	}

	result := callVerifyRemediation(t, map[string]any{"path": "/some/path", "items": []any{}})
	resp := decodeVerifyResponse(t, result)
	assert.Empty(t, resp.Results)
	assert.Equal(t, verifySummary{}, resp.Summary)
	assert.False(t, resp.Degraded)
	assert.Contains(t, toolResultText(t, result), `"results": []`, "results must serialize as an empty array, not null")
}

func TestVerifyRemediation_ArgumentValidation(t *testing.T) {
	stubScanOutcome(t, verifyOutcome(t, nil, cleanCoverage(), false))
	validItem := verifyArgItem(verifyResA, "C-0017")

	tests := []struct {
		name string
		args map[string]any
		want string
	}{
		{"missing path", map[string]any{"items": []any{validItem}}, "path argument is required"},
		{"blank path", map[string]any{"path": "  ", "items": []any{validItem}}, "path argument is required"},
		{"non-string path", map[string]any{"path": 7, "items": []any{validItem}}, "path argument must be a string"},
		{"missing items", map[string]any{"path": "/p"}, "items argument is required"},
		{"null items", map[string]any{"path": "/p", "items": nil}, "items argument is required"},
		{"items not an array", map[string]any{"path": "/p", "items": "C-0017"}, "items must be an array"},
		{"item not an object", map[string]any{"path": "/p", "items": []any{validItem, "x"}}, "items[1]: must be an object"},
		{"resource_id missing", map[string]any{"path": "/p", "items": []any{map[string]any{"control": map[string]any{"id": "C-0017"}}}}, "items[0]: resource_id must be a string"},
		{"resource_id not a string", map[string]any{"path": "/p", "items": []any{map[string]any{"resource_id": 5, "control": map[string]any{"id": "C-0017"}}}}, "items[0]: resource_id must be a string"},
		{"control missing", map[string]any{"path": "/p", "items": []any{map[string]any{"resource_id": verifyResA}}}, "items[0]: control must be an object"},
		{"control not an object", map[string]any{"path": "/p", "items": []any{map[string]any{"resource_id": verifyResA, "control": "C-0017"}}}, "items[0]: control must be an object"},
		{"control id absent", map[string]any{"path": "/p", "items": []any{map[string]any{"resource_id": verifyResA, "control": map[string]any{"name": "n"}}}}, "items[0]: control.id must be a non-empty string"},
		{"control id blank", map[string]any{"path": "/p", "items": []any{map[string]any{"resource_id": verifyResA, "control": map[string]any{"id": "  "}}}}, "items[0]: control.id must be a non-empty string"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := callVerifyRemediation(t, tc.args)
			require.True(t, result.IsError)
			var toolErr ToolError
			require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
			assert.Equal(t, ErrCodeInvalidArgument, toolErr.Code)
			assert.Contains(t, toolErr.Message, tc.want)
		})
	}

	t.Run("too many items", func(t *testing.T) {
		items := make([]any, maxVerifyItems+1)
		for i := range items {
			items[i] = validItem
		}
		result := callVerifyRemediation(t, map[string]any{"path": "/p", "items": items})
		require.True(t, result.IsError)
		assert.Contains(t, toolResultText(t, result), "more than the limit")
	})
}

func TestVerifyRemediation_ScanFailureIsAToolError(t *testing.T) {
	orig := iacScanReportFn
	t.Cleanup(func() { iacScanReportFn = orig })
	iacScanReportFn = func(*KubescapeMcpserver, context.Context, string, []string) (*iacScanOutcome, error) {
		return nil, fmt.Errorf("policy download exploded")
	}

	result := callVerifyRemediation(t, map[string]any{
		"path":  "/some/path",
		"items": []any{verifyArgItem(verifyResA, "C-0017")},
	})
	require.True(t, result.IsError)
	var toolErr ToolError
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
	assert.Equal(t, ErrCodeScanFailed, toolErr.Code)
	assert.Contains(t, toolErr.Message, "policy download exploded")
}

func TestVerifyRemediation_ScanTimeoutIsClassified(t *testing.T) {
	orig := iacScanReportFn
	t.Cleanup(func() { iacScanReportFn = orig })
	iacScanReportFn = func(*KubescapeMcpserver, context.Context, string, []string) (*iacScanOutcome, error) {
		return nil, context.DeadlineExceeded
	}

	result := callVerifyRemediation(t, map[string]any{
		"path":  "/some/path",
		"items": []any{verifyArgItem(verifyResA, "C-0017")},
	})
	require.True(t, result.IsError)
	var toolErr ToolError
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
	assert.Equal(t, ErrCodeTimeout, toolErr.Code)
}

func TestVerifyRemediation_UnparsableReportIsAToolError(t *testing.T) {
	for name, raw := range map[string]string{
		"not json":           "this is not json",
		"results wrong type": `{"results": "nope"}`,
		"coverage wrong":     `{"results": [], "scanCoverage": 7}`,
	} {
		t.Run(name, func(t *testing.T) {
			stubScanOutcome(t, &iacScanOutcome{ReportJSON: []byte(raw)})
			result := callVerifyRemediation(t, map[string]any{
				"path":  "/some/path",
				"items": []any{verifyArgItem(verifyResA, "C-0017")},
			})
			require.True(t, result.IsError, "a bad report must not become verdicts")
			var toolErr ToolError
			require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
			assert.Equal(t, ErrCodeScanFailed, toolErr.Code)
			assert.Contains(t, toolErr.Message, "failed to parse the fresh posture report")
		})
	}
}

func TestVerifyRemediation_DoesNotModifyScannedFiles(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "deployment.yaml")
	require.NoError(t, os.WriteFile(manifest, []byte(deploymentNoSecurityContext), 0o600))
	before := sha256.Sum256([]byte(deploymentNoSecurityContext))

	stubScanOutcome(t, verifyOutcome(t, []resourcesresults.Result{
		verifyResourceResult(verifyResA, verifyControl("C-0017", apis.StatusFailed, apis.SubStatusUnknown)),
	}, cleanCoverage(), false))
	tempReports := countTempReports(t)

	resp := decodeVerifyResponse(t, callVerifyRemediation(t, map[string]any{
		"path":  dir,
		"items": []any{verifyArgItem(verifyResA, "C-0017")},
	}))
	require.Len(t, resp.Results, 1)

	after, err := os.ReadFile(manifest)
	require.NoError(t, err)
	assert.Equal(t, before, sha256.Sum256(after), "verify_remediation must not modify the scanned files")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "no files may be created next to the scanned manifest")
	assert.Equal(t, tempReports, countTempReports(t), "no staged remediation report may be left behind")
}

// TestVerifyRemediation_AcceptsApplyRemediationItems feeds the items array that
// apply_remediation returns, decoded from its JSON and otherwise untouched.
func TestVerifyRemediation_AcceptsApplyRemediationItems(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "deployment.yaml"), []byte(deploymentNoSecurityContext), 0o600))
	res := remediationResource(dir, "deployment.yaml", "Deployment", "demo", 0)
	stubScanReport(t, remediationReport(dir, res,
		remediationFailedControl("C-0013", "Non-root containers",
			remediationFailedRuleWithFix("spec.template.spec.securityContext.runAsNonRoot", "true"),
		),
	))
	applied := callApplyRemediation(t, &KubescapeMcpserver{}, map[string]any{"path": dir, "control_ids": "C-0013,C-0017"})
	require.False(t, applied.IsError, toolResultText(t, applied))
	var applyResp map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, applied)), &applyResp))
	items, ok := applyResp["items"].([]any)
	require.True(t, ok)
	require.GreaterOrEqual(t, len(items), 2, "expect a patch_available item and a not_evaluated item")

	// The fresh scan: the patched resource now passes C-0013.
	stubScanOutcome(t, verifyOutcome(t, []resourcesresults.Result{
		verifyResourceResult(res.GetID(), verifyControl("C-0013", apis.StatusPassed, apis.SubStatusUnknown)),
	}, cleanCoverage(), false))

	resp := decodeVerifyResponse(t, callVerifyRemediation(t, map[string]any{"path": dir, "items": items}))
	require.Len(t, resp.Results, len(items))
	byControl := map[string]verifyResult{}
	for _, r := range resp.Results {
		byControl[r.ControlID] = r
	}
	assert.Equal(t, verdictResolved, byControl["C-0013"].Verdict)
	assert.Equal(t, res.GetID(), byControl["C-0013"].ResourceID)
	// C-0017 was requested but never evaluated: apply_remediation emits a
	// not_evaluated item with an empty resource_id, which cannot be verified.
	assert.Equal(t, verdictUnverified, byControl["C-0017"].Verdict)
	assert.Equal(t, reasonResourceIDMissing, byControl["C-0017"].Reason)
}

func TestCreateVerifyRemediationTools_RegistersVerifyRemediation(t *testing.T) {
	ksServer := &KubescapeMcpserver{s: server.NewMCPServer("kubescape-test", "test")}
	require.NotPanics(t, func() { createVerifyRemediationTools(ksServer) })

	message, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
	require.NoError(t, err)
	raw, err := json.Marshal(ksServer.s.HandleMessage(context.Background(), message))
	require.NoError(t, err)

	var listed struct {
		Result struct {
			Tools []struct {
				Name        string `json:"name"`
				Annotations struct {
					ReadOnlyHint    *bool `json:"readOnlyHint"`
					DestructiveHint *bool `json:"destructiveHint"`
				} `json:"annotations"`
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
		if tool.Name != "verify_remediation" {
			continue
		}
		found = true
		assert.Contains(t, tool.InputSchema.Properties, "path")
		assert.Contains(t, tool.InputSchema.Properties, "items")
		assert.ElementsMatch(t, []string{"path", "items"}, tool.InputSchema.Required)
		require.NotNil(t, tool.Annotations.ReadOnlyHint)
		assert.True(t, *tool.Annotations.ReadOnlyHint, "verify_remediation is read-only")
		require.NotNil(t, tool.Annotations.DestructiveHint)
		assert.False(t, *tool.Annotations.DestructiveHint)
	}
	assert.True(t, found, "verify_remediation was not registered")
}

func TestRegisterTools_IncludesVerifyRemediation(t *testing.T) {
	ksServer := &KubescapeMcpserver{s: server.NewMCPServer("kubescape-test", "test")}
	registerTools(ksServer)

	message, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
	require.NoError(t, err)
	raw, err := json.Marshal(ksServer.s.HandleMessage(context.Background(), message))
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"verify_remediation"`)
}

// TestVerifyRemediation_RealScan runs the verifier against a real in-process
// IaC scan: it plans a fix with apply_remediation, applies the patch itself,
// and verifies. It needs the policy store and is skipped without it.
func TestVerifyRemediation_RealScan(t *testing.T) {
	ksServer := &KubescapeMcpserver{policyGetter: getSharedLiveClusterPolicyGetter(t)}
	dir := t.TempDir()
	badPod := filepath.Join(dir, "bad.yaml")
	goodPod := filepath.Join(dir, "good.yaml")
	require.NoError(t, os.WriteFile(badPod, []byte(verifyRealBadPod), 0o600))
	require.NoError(t, os.WriteFile(goodPod, []byte(verifyRealGoodPod), 0o600))

	apply := func() map[string]any {
		res, err := ksServer.CallTool(context.Background(), "apply_remediation", map[string]any{"path": dir, "control_ids": "C-0017"})
		require.NoError(t, err)
		require.False(t, res.IsError, toolResultText(t, res))
		var out map[string]any
		require.NoError(t, json.Unmarshal([]byte(toolResultText(t, res)), &out))
		return out
	}
	verify := func(items []any) verifyResponse {
		res, err := ksServer.CallTool(context.Background(), "verify_remediation", map[string]any{"path": dir, "items": items})
		require.NoError(t, err)
		return decodeVerifyResponse(t, res)
	}

	planned := apply()
	items, _ := planned["items"].([]any)
	var failingItems []any
	for _, it := range items {
		if m, ok := it.(map[string]any); ok && m["resource_id"] != "" {
			failingItems = append(failingItems, it)
		}
	}
	require.Len(t, failingItems, 1, "only the bad pod fails C-0017: %v", planned)

	// Before the patch is applied the finding is still there.
	before := verify(failingItems)
	require.Len(t, before.Results, 1)
	assert.Equal(t, verdictStillFailing, before.Results[0].Verdict)

	// Apply the returned patch the way a caller would.
	files, _ := planned["files"].([]any)
	require.Len(t, files, 1)
	patched, _ := files[0].(map[string]any)["patched_yaml"].(string)
	require.NotEmpty(t, patched)
	require.NoError(t, os.WriteFile(badPod, []byte(patched), 0o600))

	after := verify(failingItems)
	require.Len(t, after.Results, 1)
	assert.Equal(t, verdictResolved, after.Results[0].Verdict, "reason: %s", after.Results[0].Reason)
	assert.False(t, after.Degraded)

	// A renamed file changes the path-sensitive resource id: not found, not resolved.
	require.NoError(t, os.Rename(badPod, filepath.Join(dir, "renamed.yaml")))
	renamed := verify(failingItems)
	require.Len(t, renamed.Results, 1)
	assert.Equal(t, verdictUnverified, renamed.Results[0].Verdict)
	assert.Equal(t, reasonResourceNotFound, renamed.Results[0].Reason)
}

const verifyRealBadPod = `apiVersion: v1
kind: Pod
metadata:
  name: bad
  namespace: default
spec:
  containers:
  - name: c
    image: nginx
`

const verifyRealGoodPod = `apiVersion: v1
kind: Pod
metadata:
  name: good
  namespace: default
spec:
  containers:
  - name: c
    image: nginx
    securityContext:
      readOnlyRootFilesystem: true
`

// TestVerifyRemediation_RealScanNeverInfersFixFromAbsence runs real in-process
// scans over layouts that change the path-sensitive resource id, or remove the
// resource. None of them may be reported as resolved.
func TestVerifyRemediation_RealScanNeverInfersFixFromAbsence(t *testing.T) {
	ksServer := &KubescapeMcpserver{policyGetter: getSharedLiveClusterPolicyGetter(t)}
	dir := t.TempDir()
	badPod := filepath.Join(dir, "bad.yaml")
	goodPod := filepath.Join(dir, "good.yaml")
	require.NoError(t, os.WriteFile(badPod, []byte(verifyRealBadPod), 0o600))
	require.NoError(t, os.WriteFile(goodPod, []byte(verifyRealGoodPod), 0o600))

	call := func(tool, path string, extra map[string]any) *mcp.CallToolResult {
		args := map[string]any{"path": path}
		for k, v := range extra {
			args[k] = v
		}
		res, err := ksServer.CallTool(context.Background(), tool, args)
		require.NoError(t, err)
		return res
	}
	applied := call("apply_remediation", dir, map[string]any{"control_ids": "C-0017"})
	require.False(t, applied.IsError, toolResultText(t, applied))
	var planned map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, applied)), &planned))
	var failing []any
	for _, it := range planned["items"].([]any) {
		if m, ok := it.(map[string]any); ok && m["resource_id"] != "" {
			failing = append(failing, it)
		}
	}
	require.Len(t, failing, 1)
	verify := func(path string) verifyResult {
		resp := decodeVerifyResponse(t, call("verify_remediation", path, map[string]any{"items": failing}))
		require.Len(t, resp.Results, 1)
		return resp.Results[0]
	}
	snapshot := func() map[string]string {
		out := map[string]string{}
		root, err := os.OpenRoot(dir)
		require.NoError(t, err)
		defer root.Close()
		fsys := root.FS()
		require.NoError(t, fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, rerr := fs.ReadFile(fsys, p)
			out[p] = string(b)
			return rerr
		}))
		return out
	}

	// A patch that does not touch the finding leaves it failing.
	before := snapshot()
	assert.Equal(t, verdictStillFailing, verify(dir).Verdict)
	assert.Equal(t, before, snapshot(), "verification must not modify any input file")

	// A different scan root yields different path-relative ids.
	assert.Equal(t, reasonResourceNotFound, verify(goodPod).Reason)
	assert.Equal(t, verdictUnverified, verify(goodPod).Verdict)

	// Moving the file under a subdirectory changes the id.
	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.Mkdir(sub, 0o700))
	require.NoError(t, os.Rename(badPod, filepath.Join(sub, "bad.yaml")))
	moved := verify(dir)
	assert.Equal(t, verdictUnverified, moved.Verdict)
	assert.Equal(t, reasonResourceNotFound, moved.Reason)

	// Deleting the resource is indistinguishable from the above and is not a fix.
	require.NoError(t, os.Remove(filepath.Join(sub, "bad.yaml")))
	deleted := verify(dir)
	assert.Equal(t, verdictUnverified, deleted.Verdict)
	assert.Equal(t, reasonResourceNotFound, deleted.Reason)
}

// TestVerifyRemediation_PathOutsideWorkspaceIsAToolError runs the real scan
// entry point: a path outside the workspace is refused before any scan and is
// reported as a tool error, never as unverified verdicts.
func TestVerifyRemediation_PathOutsideWorkspaceIsAToolError(t *testing.T) {
	workspace := t.TempDir()
	outside := t.TempDir()
	ksServer := &KubescapeMcpserver{workspaceDir: workspace}

	res, err := ksServer.CallTool(context.Background(), "verify_remediation", map[string]any{
		"path":  outside,
		"items": []any{verifyArgItem(verifyResA, "C-0017")},
	})
	require.NoError(t, err)
	require.True(t, res.IsError, toolResultText(t, res))
	assert.NotContains(t, toolResultText(t, res), `"verdict"`)
}
