package diff

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ciChange(controlID, resourceID, severity string) ControlChange {
	return ControlChange{
		ResourceID:         resourceID,
		ControlID:          controlID,
		ControlName:        "Control " + controlID,
		Severity:           severity,
		BaseStatus:         "passed",
		HeadStatus:         "failed",
		RuleName:           "rule-" + strings.ToLower(controlID),
		EvidenceType:       evidenceTypeReviewPath,
		Path:               "spec.template.spec.containers[0].securityContext.privileged",
		EvidenceResourceID: resourceID + "/pod",
	}
}

func ciChangeSet() *ChangeSet {
	low := ciChange("C-LOW", "apps/v1/default/Deployment/low", "Low")
	medium := ciChange("C-MEDIUM", "apps/v1/default/Deployment/medium", "Medium")
	high := ciChange("C-HIGH", "apps/v1/default/Deployment/high", "High")
	critical := ciChange("C-CRITICAL", "apps/v1/default/Deployment/critical", "Critical")
	incomparable := ciChange("C-INCOMPARABLE", "apps/v1/default/Deployment/incomparable", "High")
	incomparable.BaseStatus = "failed"
	incomparable.Reason = "reports use different failed evidence detail"
	resolved := ciChange("C-RESOLVED", "apps/v1/default/Deployment/resolved", "Critical")
	resolved.BaseStatus = "failed"
	resolved.HeadStatus = "passed"
	unchanged := ciChange("C-UNCHANGED", "apps/v1/default/Deployment/unchanged", "Critical")
	unchanged.BaseStatus = "failed"

	return &ChangeSet{
		New:          []ControlChange{low, critical, medium, high},
		Resolved:     []ControlChange{resolved},
		Unchanged:    []ControlChange{unchanged},
		Incomparable: []ControlChange{incomparable},
		Warnings:     []string{"included namespaces differ", "target names differ"},
	}
}

func decodeJSON[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var value T
	require.NoError(t, json.Unmarshal(raw, &value))
	return value
}

func TestRegressions_FiltersNewAndIncomparableOnly(t *testing.T) {
	regressions := Regressions(ciChangeSet(), "high")

	require.Len(t, regressions.New, 2)
	assert.Equal(t, []string{"C-CRITICAL", "C-HIGH"}, controlIDs(regressions.New))
	require.Len(t, regressions.Incomparable, 1)
	assert.Equal(t, "C-INCOMPARABLE", regressions.Incomparable[0].ControlID)
	assert.Equal(t, []string{"included namespaces differ", "target names differ"}, regressions.Warnings)
}

func TestRegressions_ClonesReturnedSlices(t *testing.T) {
	cs := ciChangeSet()

	regressions := Regressions(cs, "")
	regressions.New[0].ControlID = "changed"
	regressions.Incomparable[0].ControlID = "changed"
	regressions.Warnings[0] = "changed"

	assert.Equal(t, "C-LOW", cs.New[0].ControlID)
	assert.Equal(t, "C-INCOMPARABLE", cs.Incomparable[0].ControlID)
	assert.Equal(t, "included namespaces differ", cs.Warnings[0])
}

func TestRegressions_NilChangeSetIsEmpty(t *testing.T) {
	regressions := Regressions(nil, "")

	assert.Empty(t, regressions.New)
	assert.Empty(t, regressions.Incomparable)
	assert.Empty(t, regressions.Warnings)
}

func TestRegressionSetAll_SortsFindingsDeterministically(t *testing.T) {
	cs := &ChangeSet{
		New: []ControlChange{
			ciChange("C-LOW", "b", "Low"),
			ciChange("C-HIGH", "c", "High"),
			ciChange("C-CRITICAL", "a", "Critical"),
			ciChange("C-MEDIUM", "d", "Medium"),
		},
		Incomparable: []ControlChange{
			ciChange("C-INCOMPARABLE", "z", "Critical"),
		},
	}

	findings := Regressions(cs, "").all()

	require.Len(t, findings, 5)
	assert.Equal(t, []string{"incomparable", "new", "new", "new", "new"}, findingKinds(findings))
	assert.Equal(t, []string{"C-INCOMPARABLE", "C-CRITICAL", "C-HIGH", "C-MEDIUM", "C-LOW"}, findingControlIDs(findings))
}

func TestRegressionSetAll_UsesStableTieBreakers(t *testing.T) {
	changes := []ControlChange{
		{ResourceID: "resource-b", ControlID: "C-2", Severity: "High", RuleName: "rule-b", EvidenceType: "rule", Path: "b", Reason: "b"},
		{ResourceID: "resource-a", ControlID: "C-2", Severity: "High", RuleName: "rule-b", EvidenceType: "rule", Path: "b", Reason: "b"},
		{ResourceID: "resource-a", ControlID: "C-1", Severity: "High", RuleName: "rule-b", EvidenceType: "rule", Path: "b", Reason: "b"},
		{ResourceID: "resource-a", ControlID: "C-1", Severity: "High", RuleName: "rule-a", EvidenceType: "rule", Path: "b", Reason: "b"},
		{ResourceID: "resource-a", ControlID: "C-1", Severity: "High", RuleName: "rule-a", EvidenceType: "reviewPath", Path: "a", Reason: "a"},
	}

	findings := Regressions(&ChangeSet{New: changes}, "").all()

	require.Len(t, findings, len(changes))
	assert.Equal(t, "resource-a", findings[0].Change.ResourceID)
	assert.Equal(t, "C-1", findings[0].Change.ControlID)
	assert.Equal(t, "rule-a", findings[0].Change.RuleName)
	assert.Equal(t, "reviewPath", findings[0].Change.EvidenceType)
	assert.Equal(t, "a", findings[0].Change.Path)
	assert.Equal(t, "resource-b", findings[len(findings)-1].Change.ResourceID)
}

func TestPrintMarkdown_WritesPRFriendlyRegressionSummary(t *testing.T) {
	var output bytes.Buffer
	require.NoError(t, PrintMarkdown(&output, ciChangeSet(), "high"))

	actual := output.String()
	assert.Contains(t, actual, "# Kubescape Diff Regressions")
	assert.Contains(t, actual, "| New | 2 |")
	assert.Contains(t, actual, "| Incomparable | 1 |")
	assert.Contains(t, actual, "| Warnings | 2 |")
	assert.Contains(t, actual, "Severity threshold: high")
	assert.Contains(t, actual, "## Warnings")
	assert.Contains(t, actual, "- included namespaces differ")
	assert.Contains(t, actual, "## New Failures")
	assert.Contains(t, actual, "## Incomparable Failures")
	assert.Contains(t, actual, "Control C-CRITICAL (C-CRITICAL)")
	assert.Contains(t, actual, "reports use different failed evidence detail")
	assert.NotContains(t, actual, "C-LOW")
	assert.NotContains(t, actual, "C-MEDIUM")
	assert.NotContains(t, actual, "C-RESOLVED")
	assert.NotContains(t, actual, "C-UNCHANGED")
}

func TestPrintMarkdown_ReportsNoMatchingRegressions(t *testing.T) {
	var output bytes.Buffer
	require.NoError(t, PrintMarkdown(&output, ciChangeSet(), "critical"))

	actual := output.String()
	assert.Contains(t, actual, "| New | 1 |")
	assert.Contains(t, actual, "| Incomparable | 0 |")
	assert.Contains(t, actual, "C-CRITICAL")
	assert.NotContains(t, actual, "No new or incomparable failures")

	output.Reset()
	require.NoError(t, PrintMarkdown(&output, &ChangeSet{}, "high"))
	assert.Contains(t, output.String(), "No new or incomparable failures matched the severity threshold.")
}

func TestPrintMarkdown_EscapesTableCells(t *testing.T) {
	change := ciChange("C-PIPE", "apps/v1/default/Deployment/a|b", "High")
	change.ControlName = "Control | pipe\nnewline"
	change.Reason = "reason | pipe\nnewline"

	var output bytes.Buffer
	require.NoError(t, PrintMarkdown(&output, &ChangeSet{New: []ControlChange{change}}, ""))

	actual := output.String()
	assert.Contains(t, actual, "Control \\| pipe newline")
	assert.Contains(t, actual, "apps/v1/default/Deployment/a\\|b")
	assert.Contains(t, actual, "reason \\| pipe newline")
}

func TestPrintMarkdown_PropagatesWriterError(t *testing.T) {
	errBoom := errors.New("boom")

	err := PrintMarkdown(failingWriter{err: errBoom}, ciChangeSet(), "")

	require.ErrorIs(t, err, errBoom)
}

func TestPrintJUnit_WritesFailingTestCases(t *testing.T) {
	var output bytes.Buffer
	require.NoError(t, PrintJUnit(&output, ciChangeSet(), "high"))

	assert.True(t, strings.HasPrefix(output.String(), xml.Header))
	decoded := decodeJUnit(t, output.Bytes())

	assert.Equal(t, "Kubescape Diff", decoded.Name)
	assert.Equal(t, 3, decoded.Tests)
	assert.Equal(t, 3, decoded.Failures)
	require.Len(t, decoded.Suites, 2)
	assert.Equal(t, "kubescape diff new", decoded.Suites[0].Name)
	assert.Equal(t, 2, decoded.Suites[0].Tests)
	assert.Equal(t, 2, decoded.Suites[0].Failures)
	assert.Equal(t, "kubescape diff incomparable", decoded.Suites[1].Name)
	assert.Equal(t, 1, decoded.Suites[1].Tests)
	assert.Equal(t, 1, decoded.Suites[1].Failures)

	newCases := decoded.Suites[0].TestCases
	require.Len(t, newCases, 2)
	assert.Equal(t, "kubescape.diff/C-CRITICAL", newCases[0].Classname)
	assert.Contains(t, newCases[0].Name, "Control C-CRITICAL")
	require.NotNil(t, newCases[0].Failure)
	assert.Equal(t, "new", newCases[0].Failure.Type)
	assert.Contains(t, newCases[0].Failure.Message, "New Kubescape failure")
	assert.Contains(t, newCases[0].Failure.Contents, "Resource: apps/v1/default/Deployment/critical")
	assert.Contains(t, newCases[0].Failure.Contents, "Evidence: rule=rule-c-critical")

	incomparableCases := decoded.Suites[1].TestCases
	require.Len(t, incomparableCases, 1)
	assert.Equal(t, "incomparable", incomparableCases[0].Failure.Type)
	assert.Contains(t, incomparableCases[0].Failure.Message, "Incomparable Kubescape failure")
}

func TestPrintJUnit_OmitsEmptySuites(t *testing.T) {
	var output bytes.Buffer
	require.NoError(t, PrintJUnit(&output, &ChangeSet{New: []ControlChange{ciChange("C-HIGH", "resource", "High")}}, "high"))

	decoded := decodeJUnit(t, output.Bytes())

	require.Len(t, decoded.Suites, 1)
	assert.Equal(t, "kubescape diff new", decoded.Suites[0].Name)
}

func TestPrintJUnit_EmptyReportHasNoSuites(t *testing.T) {
	var output bytes.Buffer
	require.NoError(t, PrintJUnit(&output, &ChangeSet{}, ""))

	decoded := decodeJUnit(t, output.Bytes())

	assert.Equal(t, 0, decoded.Tests)
	assert.Equal(t, 0, decoded.Failures)
	assert.Empty(t, decoded.Suites)
}

func TestPrintJUnit_PropagatesWriterError(t *testing.T) {
	errBoom := errors.New("boom")

	err := PrintJUnit(failingWriter{err: errBoom}, ciChangeSet(), "")

	require.ErrorIs(t, err, errBoom)
}

func TestPrintSARIF_WritesCodeScanningReport(t *testing.T) {
	var output bytes.Buffer
	require.NoError(t, PrintSARIF(&output, ciChangeSet(), "high"))

	report := decodeJSON[diffSARIFReport](t, output.Bytes())

	assert.Equal(t, "2.1.0", report.Version)
	assert.Equal(t, "https://json.schemastore.org/sarif-2.1.0.json", report.Schema)
	require.Len(t, report.Runs, 1)
	run := report.Runs[0]
	assert.Equal(t, diffToolName, run.Tool.Driver.Name)
	assert.Equal(t, diffToolURI, run.Tool.Driver.InformationURI)

	require.Len(t, run.Tool.Driver.Rules, 3)
	assert.Equal(t, []string{"C-CRITICAL", "C-HIGH", "C-INCOMPARABLE"}, sarifRuleIDs(run.Tool.Driver.Rules))
	assert.Equal(t, "9.0", run.Tool.Driver.Rules[0].Properties["security-severity"])
	assert.Equal(t, "error", run.Tool.Driver.Rules[0].DefaultConfiguration.Level)

	require.Len(t, run.Results, 3)
	first := run.Results[0]
	assert.Equal(t, "C-INCOMPARABLE", first.RuleID)
	assert.Equal(t, "error", first.Level)
	assert.Contains(t, first.Message.Text, "Incomparable Kubescape failure")
	assert.Equal(t, "incomparable", first.Properties["changeType"])
	assert.Equal(t, "C-INCOMPARABLE", first.Properties["controlID"])
	assert.Equal(t, "reports use different failed evidence detail", first.Properties["incomparableReason"])
	require.Len(t, first.Locations, 1)
	assert.Equal(t, "apps/v1/default/Deployment/incomparable", first.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	assert.Equal(t, 1, first.Locations[0].PhysicalLocation.Region.StartLine)
	assert.NotEmpty(t, first.Fingerprints["kubescapeDiffFingerprint"])
}

func TestPrintSARIF_DeduplicatesRulesByControlID(t *testing.T) {
	first := ciChange("C-DUP", "apps/v1/default/Deployment/a", "High")
	second := ciChange("C-DUP", "apps/v1/default/Deployment/b", "Medium")

	var output bytes.Buffer
	require.NoError(t, PrintSARIF(&output, &ChangeSet{New: []ControlChange{first, second}}, ""))

	report := decodeJSON[diffSARIFReport](t, output.Bytes())
	require.Len(t, report.Runs, 1)
	assert.Len(t, report.Runs[0].Tool.Driver.Rules, 1)
	assert.Len(t, report.Runs[0].Results, 2)
}

func TestPrintSARIF_EmptyReportIsValid(t *testing.T) {
	var output bytes.Buffer
	require.NoError(t, PrintSARIF(&output, &ChangeSet{}, ""))

	report := decodeJSON[diffSARIFReport](t, output.Bytes())
	require.Len(t, report.Runs, 1)
	assert.Empty(t, report.Runs[0].Tool.Driver.Rules)
	assert.Empty(t, report.Runs[0].Results)
}

func TestPrintSARIF_PropagatesWriterError(t *testing.T) {
	errBoom := errors.New("boom")

	err := PrintSARIF(failingWriter{err: errBoom}, ciChangeSet(), "")

	require.ErrorIs(t, err, errBoom)
}

func TestPrintGitLabSAST_WritesGitLabSecurityReport(t *testing.T) {
	var output bytes.Buffer
	require.NoError(t, PrintGitLabSAST(&output, ciChangeSet(), "high"))

	report := decodeJSON[diffGitLabReport](t, output.Bytes())

	assert.Equal(t, diffGitLabVer, report.Version)
	assert.Equal(t, diffScanType, report.Scan.Type)
	assert.Equal(t, "success", report.Scan.Status)
	assert.Equal(t, diffScannerID, report.Scan.Scanner.ID)
	assert.Equal(t, diffToolName, report.Scan.Scanner.Vendor.Name)
	require.Len(t, report.Vulnerabilities, 3)

	first := report.Vulnerabilities[0]
	assert.Equal(t, "sast", first.Category)
	assert.Contains(t, first.Name, "Incomparable Kubescape failure")
	assert.Equal(t, "High", first.Severity)
	assert.Equal(t, diffScannerID, first.Scanner.ID)
	assert.Equal(t, "apps/v1/default/Deployment/incomparable", first.Location.File)
	assert.Equal(t, 1, first.Location.StartLine)
	require.Len(t, first.Identifiers, 1)
	assert.Equal(t, diffControlType, first.Identifiers[0].Type)
	assert.Equal(t, "C-INCOMPARABLE", first.Identifiers[0].Value)
	assert.Equal(t, "https://hub.armosec.io/docs/C-INCOMPARABLE", first.Identifiers[0].URL)
	assert.Contains(t, first.Solution, "Review scan coverage")

	newVuln := report.Vulnerabilities[1]
	assert.Equal(t, "Critical", newVuln.Severity)
	assert.Contains(t, newVuln.Solution, "Fix the failed control")
	assert.NotEmpty(t, newVuln.ID)
}

func TestPrintGitLabSAST_EmptyReportIsValid(t *testing.T) {
	var output bytes.Buffer
	require.NoError(t, PrintGitLabSAST(&output, &ChangeSet{}, ""))

	report := decodeJSON[diffGitLabReport](t, output.Bytes())

	assert.Equal(t, "success", report.Scan.Status)
	assert.Empty(t, report.Vulnerabilities)
}

func TestPrintGitLabSAST_PropagatesWriterError(t *testing.T) {
	errBoom := errors.New("boom")

	err := PrintGitLabSAST(failingWriter{err: errBoom}, ciChangeSet(), "")

	require.ErrorIs(t, err, errBoom)
}

func TestFindingDetails_IncludesUsefulFieldsAndOmitsEmptyFields(t *testing.T) {
	change := ciChange("C-HIGH", "resource", "High")

	details := findingDetails(change)

	assert.Contains(t, details, "Resource: resource")
	assert.Contains(t, details, "Control: Control C-HIGH (C-HIGH)")
	assert.Contains(t, details, "Severity: High")
	assert.Contains(t, details, "Base status: passed")
	assert.Contains(t, details, "Head status: failed")
	assert.Contains(t, details, "Rule: rule-c-high")
	assert.Contains(t, details, "Evidence: rule=rule-c-high type=failedPath path=spec.template.spec.containers[0].securityContext.privileged")
	assert.Contains(t, details, "Evidence resource: resource/pod")
	assert.NotContains(t, details, "Reason:")

	change.RuleName = ""
	change.EvidenceType = ""
	change.Path = ""
	change.EvidenceResourceID = ""
	change.Severity = ""
	change.BaseStatus = ""
	change.HeadStatus = ""

	details = findingDetails(change)
	assert.Contains(t, details, "Severity: unknown")
	assert.Contains(t, details, "Base status: unknown")
	assert.Contains(t, details, "Head status: unknown")
	assert.NotContains(t, details, "Rule:")
	assert.NotContains(t, details, "Evidence:")
	assert.NotContains(t, details, "Evidence resource:")
}

func TestFindingTitle_HandlesUnnamedControls(t *testing.T) {
	change := ControlChange{ControlID: "C-EMPTY"}

	assert.Equal(t, "New Kubescape failure: C-EMPTY", findingTitle("new", change))
	assert.Equal(t, "Incomparable Kubescape failure: C-EMPTY", findingTitle("incomparable", change))
}

func TestEvidenceLabel(t *testing.T) {
	assert.Equal(t, "rule=rule-a type=failedPath path=spec.containers[0].image", evidenceLabel(ControlChange{
		RuleName:     "rule-a",
		EvidenceType: evidenceTypeReviewPath,
		Path:         "spec.containers[0].image",
	}))
	assert.Equal(t, "rule=rule-a", evidenceLabel(ControlChange{
		RuleName:     "rule-a",
		EvidenceType: evidenceTypeControl,
	}))
	assert.Empty(t, evidenceLabel(ControlChange{}))
}

func TestStableFindingID_IsDeterministicAndSensitiveToFindingIdentity(t *testing.T) {
	change := ciChange("C-HIGH", "resource", "High")

	first := stableFindingID("new", change)
	second := stableFindingID("new", change)

	assert.Equal(t, first, second)
	assert.True(t, strings.HasPrefix(first, "kubescape-diff-"))
	assert.Len(t, first, len("kubescape-diff-")+32)

	changed := change
	changed.Path = "other-path"
	assert.NotEqual(t, first, stableFindingID("new", changed))
	assert.NotEqual(t, first, stableFindingID("incomparable", change))
}

func TestSeverityMappings(t *testing.T) {
	tests := []struct {
		severity        string
		wantSARIFLevel  string
		wantSARIFScore  string
		wantGitLabLevel string
	}{
		{"Critical", "error", "9.0", "Critical"},
		{"High", "error", "7.0", "High"},
		{"Medium", "warning", "4.0", "Medium"},
		{"Low", "note", "1.0", "Low"},
		{"Negligible", "note", "0.0", "Info"},
		{"Unknown", "note", "0.0", "Unknown"},
		{"", "note", "0.0", "Unknown"},
	}

	for _, test := range tests {
		t.Run(test.severity, func(t *testing.T) {
			assert.Equal(t, test.wantSARIFLevel, sarifLevel(test.severity))
			assert.Equal(t, test.wantSARIFScore, sarifSecuritySeverity(test.severity))
			assert.Equal(t, test.wantGitLabLevel, gitLabSeverity(test.severity))
		})
	}
}

func TestControlDocsURL(t *testing.T) {
	assert.Equal(t, "https://hub.armosec.io/docs/C-0001", controlDocsURL(" C-0001 "))
	assert.Equal(t, diffToolURI, controlDocsURL(" "))
}

func TestEncodeJSON_PropagatesWriterError(t *testing.T) {
	errBoom := errors.New("boom")

	err := encodeJSON(failingWriter{err: errBoom}, map[string]string{"hello": "world"})

	require.ErrorIs(t, err, errBoom)
}

func controlIDs(changes []ControlChange) []string {
	ids := make([]string, 0, len(changes))
	for _, change := range changes {
		ids = append(ids, change.ControlID)
	}
	return ids
}

func findingKinds(findings []ciFinding) []string {
	kinds := make([]string, 0, len(findings))
	for _, finding := range findings {
		kinds = append(kinds, finding.Kind)
	}
	return kinds
}

func findingControlIDs(findings []ciFinding) []string {
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		ids = append(ids, finding.Change.ControlID)
	}
	return ids
}

func sarifRuleIDs(rules []diffSARIFRule) []string {
	ids := make([]string, 0, len(rules))
	for _, rule := range rules {
		ids = append(ids, rule.ID)
	}
	sort.Strings(ids)
	return ids
}

func decodeJUnit(t *testing.T, raw []byte) diffJUnitSuites {
	t.Helper()
	raw = bytes.TrimPrefix(raw, []byte(xml.Header))
	var suites diffJUnitSuites
	require.NoError(t, xml.Unmarshal(raw, &suites))
	return suites
}
