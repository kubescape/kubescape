package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// selectionFramework has one control with a section number (C-0286), one
// without (C-0012), and two controls that share the section number X-1.
const selectionFramework = `{"name":"fixture","controls":[
 {"controlID":"C-0286","id":"CIS-3.1.1","name":"a"},
 {"controlID":"C-0012","name":"b"},
 {"controlID":"C-0101","id":"X-1","name":"c"},
 {"controlID":"C-0102","id":"X-1","name":"d"}]}`

func selectionServer(t *testing.T) *KubescapeMcpserver {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fw.json")
	require.NoError(t, os.WriteFile(path, []byte(selectionFramework), 0o600))
	ks := &KubescapeMcpserver{}
	ks.startPolicyLoad(func() getter.IPolicyGetter { return getter.NewLoadPolicy([]string{path}) })
	return ks
}

func validateSelection(t *testing.T, ks *KubescapeMcpserver, controlIDs any) scanSelectionValidation {
	t.Helper()
	res, err := ks.CallTool(context.Background(), "validate_scan_selection", map[string]any{"control_ids": controlIDs})
	require.NoError(t, err)
	require.False(t, res.IsError, toolResultText(t, res))
	var got scanSelectionValidation
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, res)), &got))
	return got
}

func TestValidateScanSelection_Resolves(t *testing.T) {
	ks := selectionServer(t)

	got := validateSelection(t, ks, []any{"C-0286", "C-0012"})
	assert.True(t, got.Valid)
	assert.Equal(t, []resolvedControl{{Input: "C-0286", ControlID: "C-0286"}, {Input: "C-0012", ControlID: "C-0012"}}, got.Resolved)

	got = validateSelection(t, ks, " cis-3.1.1 ,c-0012")
	assert.True(t, got.Valid)
	assert.Equal(t, []resolvedControl{{Input: "cis-3.1.1", ControlID: "C-0286"}, {Input: "c-0012", ControlID: "C-0012"}}, got.Resolved, "a comma string is split and trimmed, and the canonical ID is reported")
}

func TestValidateScanSelection_ReportsEveryProblem(t *testing.T) {
	ks := selectionServer(t)

	got := validateSelection(t, ks, []any{"C-9999", "C-0012", "x-1", "CIS-9.9.9", "c-9999"})
	assert.False(t, got.Valid)
	assert.Equal(t, []resolvedControl{{Input: "C-0012", ControlID: "C-0012"}}, got.Resolved)
	assert.Equal(t, []string{"C-9999", "CIS-9.9.9"}, got.Unknown, "unknown identifiers are listed once, in input order")
	assert.Equal(t, []ambiguousControl{{Input: "x-1", Matches: []string{"C-0101", "C-0102"}}}, got.Ambiguous)
	assert.Empty(t, got.Duplicates)
}

func TestValidateScanSelection_Duplicates(t *testing.T) {
	ks := selectionServer(t)

	got := validateSelection(t, ks, []any{"CIS-3.1.1", "c-0286", "C-0286", "C-0012", "C-0012"})
	assert.True(t, got.Valid, "naming a control twice is not an invalid selection")
	assert.Equal(t, []resolvedControl{{Input: "CIS-3.1.1", ControlID: "C-0286"}, {Input: "C-0012", ControlID: "C-0012"}}, got.Resolved)
	assert.Equal(t, []duplicateControl{
		{Input: "c-0286", MatchesInput: "CIS-3.1.1", ControlID: "C-0286"},
		{Input: "C-0286", MatchesInput: "CIS-3.1.1", ControlID: "C-0286"},
		{Input: "C-0012", MatchesInput: "C-0012", ControlID: "C-0012"},
	}, got.Duplicates)
}

func TestValidateScanSelection_EmptyListsAreArrays(t *testing.T) {
	ks := selectionServer(t)
	res, err := ks.CallTool(context.Background(), "validate_scan_selection", map[string]any{"control_ids": "C-0012"})
	require.NoError(t, err)
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, res)), &raw))
	for _, field := range []string{"unknown", "ambiguous", "duplicates"} {
		assert.JSONEq(t, `[]`, string(raw[field]), field)
	}
}

func TestValidateScanSelection_InvalidArguments(t *testing.T) {
	ks := selectionServer(t)
	for name, arguments := range map[string]map[string]any{
		"missing":         {},
		"null":            {"control_ids": nil},
		"wrong type":      {"control_ids": 7},
		"non-string item": {"control_ids": []any{"C-0012", 7}},
		"empty string":    {"control_ids": ""},
		"empty array":     {"control_ids": []any{}},
		"whitespace":      {"control_ids": []any{"  ", "\t"}},
		"only commas":     {"control_ids": " , ,"},
	} {
		t.Run(name, func(t *testing.T) {
			res, err := ks.CallTool(context.Background(), "validate_scan_selection", arguments)
			require.NoError(t, err)
			te := toolErrorOf(t, res)
			assert.Equal(t, ErrCodeInvalidArgument, te.Code)
			assert.Equal(t, "control_ids", te.Details["argument"])
		})
	}
}

// With the catalog still loading, nothing can be said about the identifiers.
func TestValidateScanSelection_CatalogNotReady(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	ks := &KubescapeMcpserver{policyReadyWait: 25 * time.Millisecond}
	load, _ := blockedLoad(&fakePolicyGetter{}, release)
	ks.startPolicyLoad(load)

	res, err := ks.CallTool(context.Background(), "validate_scan_selection", map[string]any{"control_ids": "C-0012"})
	require.NoError(t, err)
	te := toolErrorOf(t, res)
	assert.Equal(t, ErrCodeTimeout, te.Code)
	assert.Contains(t, te.Message, "policy bundle is still loading")
}

// failingControlGetter fails every control lookup the way a broken catalog does.
type failingControlGetter struct {
	getter.IPolicyGetter
	err error
}

func (f failingControlGetter) GetControl(string) (*reporthandling.Control, error) { return nil, f.err }

func TestValidateScanSelection_CatalogFailureIsNotUnknown(t *testing.T) {
	boom := errors.New("policy catalog unavailable: file not found")
	ks := &KubescapeMcpserver{}
	ks.startPolicyLoad(func() getter.IPolicyGetter { return failingControlGetter{err: boom} })

	res, err := ks.CallTool(context.Background(), "validate_scan_selection", map[string]any{"control_ids": []any{"C-0012", "C-0286"}})
	require.NoError(t, err)
	te := toolErrorOf(t, res)
	assert.Equal(t, ErrCodeScanFailed, te.Code, "a catalog failure is not a bad selection")
	assert.Contains(t, te.Message, "policy catalog unavailable")
}

// The tool must work with no cluster: it never builds a Kubernetes client.
func TestValidateScanSelection_NeedsNoCluster(t *testing.T) {
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "missing"))
	ks := selectionServer(t)

	got := validateSelection(t, ks, "C-0012")
	assert.True(t, got.Valid)
	assert.Nil(t, ks.k8sClient)
}

func TestValidateScanSelection_Registration(t *testing.T) {
	ks := &KubescapeMcpserver{s: server.NewMCPServer("test", "0")}
	createPolicyListingTools(ks)

	resp := ks.s.HandleMessage(context.Background(), json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	raw, err := json.Marshal(resp)
	require.NoError(t, err)
	var listed struct {
		Result struct {
			Tools []mcp.Tool `json:"tools"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(raw, &listed))

	var tool *mcp.Tool
	for i := range listed.Result.Tools {
		if listed.Result.Tools[i].Name == "validate_scan_selection" {
			tool = &listed.Result.Tools[i]
		}
	}
	require.NotNil(t, tool, "validate_scan_selection must be registered")
	require.NotNil(t, tool.Annotations.ReadOnlyHint)
	assert.True(t, *tool.Annotations.ReadOnlyHint)
	assert.Equal(t, []string{"control_ids"}, tool.InputSchema.Required)
	assert.NotContains(t, tool.InputSchema.Properties, "framework")
	assert.NotContains(t, tool.InputSchema.Properties, "namespace")
}

// scan_controls reports a selection the catalog cannot resolve as a bad
// argument, and a lookup failure as a failed scan.
func TestClassifyScanError_ControlSelection(t *testing.T) {
	unknown := fmt.Errorf("failed to collect Control policies: %w", &lookupErr{getter.ErrControlNotFound})
	ambiguous := fmt.Errorf("failed to collect Control policies: %w", &getter.AmbiguousControlError{Identifier: "x-1", Matches: []string{"C-0101", "C-0102"}})
	catalog := fmt.Errorf("failed to collect Control policies: %w", errors.New("catalog: file not found"))

	assert.Equal(t, ErrCodeInvalidArgument, classifyScanError(unknown))
	assert.Equal(t, ErrCodeInvalidArgument, classifyScanError(ambiguous))
	assert.Equal(t, ErrCodeScanFailed, classifyScanError(catalog))
	assert.Equal(t, ErrCodeTimeout, classifyScanError(fmt.Errorf("x: %w", errPolicyNotReady)), "not-ready stays a timeout")

	assert.Contains(t, classifyScanErrorMessage(ErrCodeInvalidArgument, "control", unknown), "invalid control selection")

	assert.Equal(t, map[string]any{"argument": "control_ids"}, controlSelectionErrorDetails(ErrCodeInvalidArgument, unknown))
	assert.Equal(t, map[string]any{"argument": "control_ids", "matches": []string{"C-0101", "C-0102"}},
		controlSelectionErrorDetails(ErrCodeInvalidArgument, ambiguous))
	assert.Nil(t, controlSelectionErrorDetails(ErrCodeScanFailed, catalog))
}

type lookupErr struct{ is error }

func (e *lookupErr) Error() string        { return "control 'C-9999' not found" }
func (e *lookupErr) Is(target error) bool { return target == e.is }
