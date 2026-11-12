package mcpserver

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/kubescape/kubescape/v4/core/pkg/remediationverify"
)

// The verdicts, reason codes and response types are the shared verifier's, so
// the tool and `kubescape fix --verify` cannot disagree about what is resolved.
// They are named here as they were before the logic moved, which keeps the
// tool's response exactly as it was.
const (
	verdictResolved     = remediationverify.VerdictResolved
	verdictStillFailing = remediationverify.VerdictStillFailing
	verdictUnverified   = remediationverify.VerdictUnverified
)

const (
	reasonControlPassed        = remediationverify.ReasonControlPassed
	reasonControlFailed        = remediationverify.ReasonControlFailed
	reasonResourceIDMissing    = remediationverify.ReasonResourceIDMissing
	reasonResourceNotFound     = remediationverify.ReasonResourceNotFound
	reasonAmbiguousResource    = remediationverify.ReasonAmbiguousResource
	reasonControlNotFound      = remediationverify.ReasonControlNotFound
	reasonAmbiguousControl     = remediationverify.ReasonAmbiguousControl
	reasonControlNotEvaluated  = remediationverify.ReasonControlNotEvaluated
	reasonControlSubStatus     = remediationverify.ReasonControlSubStatus
	reasonControlStatusUnknown = remediationverify.ReasonControlStatusUnknown
	reasonCoverageInsufficient = remediationverify.ReasonCoverageInsufficient
)

// maxVerifyItems bounds the items one call verifies, so a single request cannot
// make the response unbounded.
const maxVerifyItems = 1000

// verifyItem is the part of one apply_remediation item the verifier reads. The
// caller passes apply_remediation's items unchanged; every other field of an
// item is ignored.
type (
	verifyItem     = remediationverify.Item
	verifyResult   = remediationverify.Result
	verifySummary  = remediationverify.Summary
	verifyResponse = remediationverify.Response
)

func createVerifyRemediationTools(ksServer *KubescapeMcpserver) {
	verifyRemediationTool := mcp.NewTool(
		"verify_remediation",
		mcp.WithDescription("Check whether findings listed by apply_remediation are fixed, after the caller has applied the changes to local IaC. Rescans path once and returns one verdict per item, in input order: resolved only when the original resource is found in the fresh scan and the control is reported as passed with a complete scan; still_failing when the control is reported as failed; unverified, with a reason code, whenever that cannot be established. A missing resource or control is never a resolution: IaC resource IDs depend on the file path relative to the scan root and the document's position in its file, so a renamed or moved file, a reordered document or a different path root all show up as resource_not_found. Read-only: it does not apply patches or modify any file."),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("The same local YAML file or directory root that was passed to apply_remediation, now holding the applied changes."),
		),
		mcp.WithArray("items",
			mcp.Required(),
			mcp.Items(map[string]any{
				"type": "object",
				"properties": map[string]any{
					"resource_id": map[string]any{"type": "string"},
					"control": map[string]any{
						"type":       "object",
						"properties": map[string]any{"id": map[string]any{"type": "string"}},
						"required":   []string{"id"},
					},
				},
				"required": []string{"resource_id", "control"},
			}),
			mcp.Description("The items array returned by apply_remediation, passed unchanged. Only resource_id and control.id are read. Items without a resource_id (not_evaluated items) are returned as unverified."),
		),
	)
	ksServer.s.AddTool(verifyRemediationTool, ksServer.toolHandler(verifyRemediationTool.Name))
}

// parseVerifyItems decodes the items argument. A malformed item fails the whole
// call rather than being dropped, so the output always lines up with the input.
func parseVerifyItems(arguments map[string]any) ([]verifyItem, *mcp.CallToolResult) {
	raw, present := arguments["items"]
	if !present || raw == nil {
		return nil, mcpToolError(ErrCodeInvalidArgument, "items argument is required", map[string]any{"argument": "items"})
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, mcpToolError(ErrCodeInvalidArgument, "items must be an array", map[string]any{"argument": "items"})
	}
	if len(list) > maxVerifyItems {
		return nil, mcpToolError(ErrCodeInvalidArgument, fmt.Sprintf("items has %d entries, more than the limit of %d", len(list), maxVerifyItems), map[string]any{"argument": "items"})
	}

	items := make([]verifyItem, len(list))
	for i, entry := range list {
		obj, ok := entry.(map[string]any)
		if !ok {
			return nil, invalidVerifyItem(i, "must be an object")
		}
		resourceID, ok := obj["resource_id"].(string)
		if !ok {
			return nil, invalidVerifyItem(i, "resource_id must be a string")
		}
		control, ok := obj["control"].(map[string]any)
		if !ok {
			return nil, invalidVerifyItem(i, "control must be an object")
		}
		controlID, ok := control["id"].(string)
		if !ok || strings.TrimSpace(controlID) == "" {
			return nil, invalidVerifyItem(i, "control.id must be a non-empty string")
		}
		items[i] = verifyItem{ResourceID: resourceID, ControlID: strings.TrimSpace(controlID)}
	}
	return items, nil
}

func invalidVerifyItem(index int, problem string) *mcp.CallToolResult {
	return mcpToolError(ErrCodeInvalidArgument,
		fmt.Sprintf("items[%d]: %s", index, problem),
		map[string]any{"argument": "items", "index": index})
}

// verifyScanKey is the in-flight coalescing key of the scan behind one
// verify_remediation call. The scan depends only on the path and the controls;
// the verdicts are computed per caller afterwards.
func verifyScanKey(path string, controlIDs []string) string {
	return fmt.Sprintf("verify_remediation:%s:%s", url.QueryEscape(path), url.QueryEscape(strings.Join(controlIDs, ",")))
}

// verifyControlIDs returns the distinct control IDs of the items, normalized
// and sorted, which is the control set the fresh scan has to cover.
func verifyControlIDs(items []verifyItem) []string {
	return remediationverify.ControlIDs(items)
}

// verifyRemediationReport classifies every item against the fresh scan's
// report. A report that cannot be parsed is returned as an error; it is never
// turned into verdicts.
func verifyRemediationReport(outcome *iacScanOutcome, items []verifyItem) ([]byte, error) {
	resp, err := remediationverify.ClassifyReportJSON(outcome.ReportJSON, outcome.Degraded, items)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(resp, "", "  ")
}
