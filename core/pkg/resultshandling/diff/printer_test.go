package diff

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

func printableChange() ControlChange {
	return ControlChange{
		ResourceID:         "apps/v1/default/Deployment/api",
		ControlID:          "C-1000",
		ControlName:        "Require a security context",
		Severity:           "High",
		BaseStatus:         "failed",
		HeadStatus:         "failed",
		RuleName:           "require-security-context",
		EvidenceType:       evidenceTypeReviewPath,
		Path:               "spec.template.spec.containers[0].securityContext.privileged",
		EvidenceResourceID: "apps/v1/default/Pod/api-abc",
	}
}

func TestPrintPretty_PrintsEvidenceAndAllBuckets(t *testing.T) {
	newChange := printableChange()
	resolvedChange := printableChange()
	resolvedChange.Path = "spec.template.spec.hostPID"
	unchangedChange := printableChange()
	unchangedChange.Path = "spec.template.spec.hostIPC"
	incomparableChange := printableChange()
	incomparableChange.Path = "spec.template.spec.hostNetwork"
	incomparableChange.Reason = "head scan coverage was degraded"
	changes := &ChangeSet{
		New:          []ControlChange{newChange},
		Resolved:     []ControlChange{resolvedChange},
		Unchanged:    []ControlChange{unchangedChange},
		Incomparable: []ControlChange{incomparableChange},
		Warnings:     []string{"included namespaces differ"},
	}

	var output bytes.Buffer
	PrintPretty(&output, changes)
	actual := output.String()

	assert.Contains(t, actual, "WARNING: included namespaces differ")
	assert.Contains(t, actual, "New failures (1)")
	assert.Contains(t, actual, "Resolved (1)")
	assert.Contains(t, actual, "Still failing (unchanged) (1)")
	assert.Contains(t, actual, "Incomparable (1)")
	assert.Contains(t, actual, "+ [High] Require a security context (C-1000)")
	assert.Contains(t, actual, "Resource: apps/v1/default/Deployment/api")
	assert.Contains(t, actual, "Rule: require-security-context")
	assert.Contains(t, actual, "Evidence: reviewPath spec.template.spec.containers[0].securityContext.privileged")
	assert.Contains(t, actual, "Evidence resource: apps/v1/default/Pod/api-abc")
	assert.Contains(t, actual, "Reason: head scan coverage was degraded")
	assert.Contains(t, actual, "Summary: 1 new, 1 resolved, 1 unchanged, 1 incomparable")
}

func TestPrintPretty_OmitsEmptySectionsAndEvidenceDetails(t *testing.T) {
	changes := &ChangeSet{
		New: []ControlChange{{
			ResourceID:   "resource",
			ControlID:    "C-0001",
			ControlName:  "Legacy control",
			Severity:     "Low",
			BaseStatus:   "passed",
			HeadStatus:   "failed",
			EvidenceType: evidenceTypeControl,
		}},
	}

	var output bytes.Buffer
	PrintPretty(&output, changes)
	actual := output.String()

	assert.Contains(t, actual, "New failures (1)")
	assert.NotContains(t, actual, "Resolved (")
	assert.NotContains(t, actual, "Still failing")
	assert.NotContains(t, actual, "Incomparable (")
	assert.NotContains(t, actual, "Rule:")
	assert.NotContains(t, actual, "Evidence:")
	assert.NotContains(t, actual, "Evidence resource:")
	assert.NotContains(t, actual, "Reason:")
	assert.Contains(t, actual, "Summary: 1 new, 0 resolved, 0 unchanged, 0 incomparable")
}

func TestPrintPretty_SameEvidenceResourceIsNotRepeated(t *testing.T) {
	change := printableChange()
	change.EvidenceResourceID = change.ResourceID

	var output bytes.Buffer
	PrintPretty(&output, &ChangeSet{New: []ControlChange{change}})

	assert.NotContains(t, output.String(), "Evidence resource:")
}

func TestPrintPretty_PathlessRuleEvidence(t *testing.T) {
	change := printableChange()
	change.EvidenceType = evidenceTypeRule
	change.Path = ""
	change.EvidenceResourceID = ""

	var output bytes.Buffer
	PrintPretty(&output, &ChangeSet{New: []ControlChange{change}})

	assert.Contains(t, output.String(), "Rule: require-security-context")
	assert.Contains(t, output.String(), "Evidence: rule\n")
}

func TestPrintJSON_PreservesEvidenceSchema(t *testing.T) {
	change := printableChange()
	changes := &ChangeSet{
		New:          []ControlChange{change},
		Resolved:     []ControlChange{},
		Unchanged:    []ControlChange{},
		Incomparable: []ControlChange{{Reason: "unsafe comparison"}},
		Warnings:     []string{"scope differs"},
	}

	var output bytes.Buffer
	require.NoError(t, PrintJSON(&output, changes))

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(output.Bytes(), &decoded))
	require.Contains(t, decoded, "new")
	require.Contains(t, decoded, "resolved")
	require.Contains(t, decoded, "unchanged")
	require.Contains(t, decoded, "incomparable")
	require.Contains(t, decoded, "warnings")
	newItems, ok := decoded["new"].([]any)
	require.True(t, ok)
	require.Len(t, newItems, 1)
	item, ok := newItems[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "require-security-context", item["ruleName"])
	assert.Equal(t, "reviewPath", item["evidenceType"])
	assert.Equal(t, "spec.template.spec.containers[0].securityContext.privileged", item["path"])
	assert.Equal(t, "apps/v1/default/Pod/api-abc", item["evidenceResourceID"])
}

func TestPrintJSON_OmitsOptionalCompatibilityFields(t *testing.T) {
	changes := &ChangeSet{
		New:       []ControlChange{{ResourceID: "resource", ControlID: "control"}},
		Resolved:  []ControlChange{},
		Unchanged: []ControlChange{},
	}

	var output bytes.Buffer
	require.NoError(t, PrintJSON(&output, changes))
	actual := output.String()

	assert.NotContains(t, actual, `"incomparable"`)
	assert.NotContains(t, actual, `"warnings"`)
	assert.NotContains(t, actual, `"ruleName"`)
	assert.NotContains(t, actual, `"evidenceType"`)
	assert.NotContains(t, actual, `"path"`)
	assert.NotContains(t, actual, `"evidenceResourceID"`)
	assert.NotContains(t, actual, `"reason"`)
}

func TestPrintYAML_PreservesNewBucketsAndEvidence(t *testing.T) {
	change := printableChange()
	changes := &ChangeSet{
		New:          []ControlChange{change},
		Resolved:     []ControlChange{},
		Unchanged:    []ControlChange{},
		Incomparable: []ControlChange{{Reason: "not evaluated"}},
		Warnings:     []string{"coverage degraded"},
	}

	var output bytes.Buffer
	require.NoError(t, PrintYAML(&output, changes))
	actual := output.String()

	assert.Contains(t, actual, "ruleName: require-security-context")
	assert.Contains(t, actual, "evidenceType: reviewPath")
	assert.Contains(t, actual, "path: spec.template.spec.containers[0].securityContext.privileged")
	assert.Contains(t, actual, "incomparable:")
	assert.Contains(t, actual, "reason: not evaluated")
	assert.Contains(t, actual, "warnings:")
	assert.Contains(t, actual, "- coverage degraded")

	var decoded map[string]any
	require.NoError(t, yaml.Unmarshal(output.Bytes(), &decoded))
	assert.Contains(t, decoded, "new")
	assert.Contains(t, decoded, "incomparable")
	assert.Contains(t, decoded, "warnings")
}
