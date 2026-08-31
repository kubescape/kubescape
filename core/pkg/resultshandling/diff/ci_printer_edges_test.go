package diff

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCIPrinters_HandleMinimalControlChanges(t *testing.T) {
	change := ControlChange{
		ResourceID: "resource-only",
		ControlID:  "C-MIN",
		Severity:   "Low",
		HeadStatus: "failed",
	}
	cs := &ChangeSet{New: []ControlChange{change}}

	var markdown bytes.Buffer
	require.NoError(t, PrintMarkdown(&markdown, cs, ""))
	assert.Contains(t, markdown.String(), "C-MIN")
	assert.Contains(t, markdown.String(), "resource-only")
	assert.NotContains(t, markdown.String(), "rule=")

	var junit bytes.Buffer
	require.NoError(t, PrintJUnit(&junit, cs, ""))
	decodedJUnit := decodeJUnit(t, junit.Bytes())
	require.Len(t, decodedJUnit.Suites, 1)
	require.Len(t, decodedJUnit.Suites[0].TestCases, 1)
	assert.Equal(t, "kubescape.diff/C-MIN", decodedJUnit.Suites[0].TestCases[0].Classname)
	assert.Equal(t, "resource-only", decodedJUnit.Suites[0].TestCases[0].Name)
	assert.Contains(t, decodedJUnit.Suites[0].TestCases[0].Failure.Contents, "Control: (C-MIN)")

	var sarif bytes.Buffer
	require.NoError(t, PrintSARIF(&sarif, cs, ""))
	decodedSARIF := decodeJSON[diffSARIFReport](t, sarif.Bytes())
	require.Len(t, decodedSARIF.Runs, 1)
	require.Len(t, decodedSARIF.Runs[0].Results, 1)
	assert.Equal(t, "C-MIN", decodedSARIF.Runs[0].Results[0].RuleID)
	assert.Equal(t, "resource-only", decodedSARIF.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)

	var gitlab bytes.Buffer
	require.NoError(t, PrintGitLabSAST(&gitlab, cs, ""))
	decodedGitLab := decodeJSON[diffGitLabReport](t, gitlab.Bytes())
	require.Len(t, decodedGitLab.Vulnerabilities, 1)
	assert.Equal(t, "C-MIN", decodedGitLab.Vulnerabilities[0].Identifiers[0].Value)
	assert.Equal(t, "resource-only", decodedGitLab.Vulnerabilities[0].Location.File)
}

func TestCIPrinters_HandlePathlessRuleChanges(t *testing.T) {
	change := ciChange("C-RULE", "apps/v1/default/Deployment/rule", "Medium")
	change.EvidenceType = evidenceTypeRule
	change.Path = ""
	change.EvidenceResourceID = ""
	cs := &ChangeSet{New: []ControlChange{change}}

	var markdown bytes.Buffer
	require.NoError(t, PrintMarkdown(&markdown, cs, ""))
	assert.Contains(t, markdown.String(), "rule=rule-c-rule")
	assert.NotContains(t, markdown.String(), "path=")

	var junit bytes.Buffer
	require.NoError(t, PrintJUnit(&junit, cs, ""))
	assert.Contains(t, junit.String(), "Evidence: rule=rule-c-rule")
	assert.NotContains(t, junit.String(), "Evidence resource:")

	var sarif bytes.Buffer
	require.NoError(t, PrintSARIF(&sarif, cs, ""))
	sarifReport := decodeJSON[diffSARIFReport](t, sarif.Bytes())
	require.Len(t, sarifReport.Runs[0].Results, 1)
	assert.Equal(t, "rule", sarifReport.Runs[0].Results[0].Properties["evidenceType"])
	assert.Equal(t, "", sarifReport.Runs[0].Results[0].Properties["evidencePath"])

	var gitlab bytes.Buffer
	require.NoError(t, PrintGitLabSAST(&gitlab, cs, ""))
	gitlabReport := decodeJSON[diffGitLabReport](t, gitlab.Bytes())
	require.Len(t, gitlabReport.Vulnerabilities, 1)
	assert.Contains(t, gitlabReport.Vulnerabilities[0].Description, "Evidence: rule=rule-c-rule")
	assert.NotContains(t, gitlabReport.Vulnerabilities[0].Description, "Evidence resource:")
}

func TestCIPrinters_HandleResourceScopedControlChanges(t *testing.T) {
	change := ciChange("C-CONTROL", "apps/v1/default/Deployment/control", "High")
	change.RuleName = ""
	change.EvidenceType = evidenceTypeControl
	change.Path = ""
	change.EvidenceResourceID = change.ResourceID
	cs := &ChangeSet{New: []ControlChange{change}}

	var markdown bytes.Buffer
	require.NoError(t, PrintMarkdown(&markdown, cs, ""))
	assert.Contains(t, markdown.String(), "| - |")

	var junit bytes.Buffer
	require.NoError(t, PrintJUnit(&junit, cs, ""))
	decodedJUnit := decodeJUnit(t, junit.Bytes())
	require.Len(t, decodedJUnit.Suites[0].TestCases, 1)
	assert.Equal(t, "Control C-CONTROL / apps/v1/default/Deployment/control", decodedJUnit.Suites[0].TestCases[0].Name)
	assert.NotContains(t, decodedJUnit.Suites[0].TestCases[0].Failure.Contents, "Evidence:")

	var sarif bytes.Buffer
	require.NoError(t, PrintSARIF(&sarif, cs, ""))
	sarifReport := decodeJSON[diffSARIFReport](t, sarif.Bytes())
	require.Len(t, sarifReport.Runs[0].Results, 1)
	assert.Equal(t, "control", sarifReport.Runs[0].Results[0].Properties["evidenceType"])

	var gitlab bytes.Buffer
	require.NoError(t, PrintGitLabSAST(&gitlab, cs, ""))
	gitlabReport := decodeJSON[diffGitLabReport](t, gitlab.Bytes())
	require.Len(t, gitlabReport.Vulnerabilities, 1)
	assert.NotContains(t, gitlabReport.Vulnerabilities[0].Description, "Evidence:")
}

func TestStableFindingID_UsesReasonOnlyForIncomparableIdentity(t *testing.T) {
	change := ciChange("C-ID", "resource", "High")
	baseID := stableFindingID("new", change)

	reasonChanged := change
	reasonChanged.Reason = "scope changed"

	assert.NotEqual(t, baseID, stableFindingID("new", reasonChanged))
	assert.NotEqual(t, stableFindingID("incomparable", change), stableFindingID("incomparable", reasonChanged))
}

func TestCIJSONPrintersEmitIndentedJSON(t *testing.T) {
	cs := &ChangeSet{New: []ControlChange{ciChange("C-JSON", "resource", "High")}}

	var sarif bytes.Buffer
	require.NoError(t, PrintSARIF(&sarif, cs, ""))
	assert.Contains(t, sarif.String(), "\n  ")
	assert.True(t, json.Valid(sarif.Bytes()))

	var gitlab bytes.Buffer
	require.NoError(t, PrintGitLabSAST(&gitlab, cs, ""))
	assert.Contains(t, gitlab.String(), "\n  ")
	assert.True(t, json.Valid(gitlab.Bytes()))
}

func TestCIJUnitPrinterEmitsValidXMLDocument(t *testing.T) {
	var output bytes.Buffer
	require.NoError(t, PrintJUnit(&output, ciChangeSet(), "high"))

	assert.True(t, bytes.HasPrefix(output.Bytes(), []byte(xml.Header)))
	payload := bytes.TrimPrefix(output.Bytes(), []byte(xml.Header))
	assert.NoError(t, xml.Unmarshal(payload, &diffJUnitSuites{}))
}

func TestCIPrintersSeverityThresholdWithOnlyFilteredWarnings(t *testing.T) {
	cs := &ChangeSet{
		New:      []ControlChange{ciChange("C-LOW", "resource", "Low")},
		Warnings: []string{"scope differs"},
	}

	var markdown bytes.Buffer
	require.NoError(t, PrintMarkdown(&markdown, cs, "critical"))
	assert.Contains(t, markdown.String(), "| New | 0 |")
	assert.Contains(t, markdown.String(), "| Warnings | 1 |")
	assert.Contains(t, markdown.String(), "scope differs")

	var sarif bytes.Buffer
	require.NoError(t, PrintSARIF(&sarif, cs, "critical"))
	sarifReport := decodeJSON[diffSARIFReport](t, sarif.Bytes())
	require.Len(t, sarifReport.Runs, 1)
	assert.Empty(t, sarifReport.Runs[0].Results)

	var gitlab bytes.Buffer
	require.NoError(t, PrintGitLabSAST(&gitlab, cs, "critical"))
	gitlabReport := decodeJSON[diffGitLabReport](t, gitlab.Bytes())
	assert.Empty(t, gitlabReport.Vulnerabilities)
}

func TestCIPrintersDoNotMutateInputChangeSet(t *testing.T) {
	cs := ciChangeSet()
	before, err := json.Marshal(cs)
	require.NoError(t, err)

	var markdown bytes.Buffer
	var junit bytes.Buffer
	var sarif bytes.Buffer
	var gitlab bytes.Buffer
	require.NoError(t, PrintMarkdown(&markdown, cs, "high"))
	require.NoError(t, PrintJUnit(&junit, cs, "high"))
	require.NoError(t, PrintSARIF(&sarif, cs, "high"))
	require.NoError(t, PrintGitLabSAST(&gitlab, cs, "high"))

	after, err := json.Marshal(cs)
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after))
}

func TestCIPrintersHandleNilChangeSet(t *testing.T) {
	var markdown bytes.Buffer
	require.NoError(t, PrintMarkdown(&markdown, nil, ""))
	assert.Contains(t, markdown.String(), "| New | 0 |")

	var junit bytes.Buffer
	require.NoError(t, PrintJUnit(&junit, nil, ""))
	assert.Equal(t, 0, decodeJUnit(t, junit.Bytes()).Tests)

	var sarif bytes.Buffer
	require.NoError(t, PrintSARIF(&sarif, nil, ""))
	sarifReport := decodeJSON[diffSARIFReport](t, sarif.Bytes())
	assert.Empty(t, sarifReport.Runs[0].Results)

	var gitlab bytes.Buffer
	require.NoError(t, PrintGitLabSAST(&gitlab, nil, ""))
	gitlabReport := decodeJSON[diffGitLabReport](t, gitlab.Bytes())
	assert.Empty(t, gitlabReport.Vulnerabilities)
}
