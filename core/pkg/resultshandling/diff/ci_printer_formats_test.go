package diff

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCIPrinters_RespectSeverityThresholds(t *testing.T) {
	tests := []struct {
		name        string
		threshold   string
		wantNew     []string
		wantIncomp  []string
		wantSARIF   []string
		wantGitLab  []string
		wantJUnit   int
		wantDetails []string
	}{
		{
			name:        "all severities",
			threshold:   "",
			wantNew:     []string{"C-LOW", "C-CRITICAL", "C-MEDIUM", "C-HIGH"},
			wantIncomp:  []string{"C-INCOMPARABLE"},
			wantSARIF:   []string{"C-INCOMPARABLE", "C-CRITICAL", "C-HIGH", "C-MEDIUM", "C-LOW"},
			wantGitLab:  []string{"C-INCOMPARABLE", "C-CRITICAL", "C-HIGH", "C-MEDIUM", "C-LOW"},
			wantJUnit:   5,
			wantDetails: []string{"Control C-CRITICAL", "Control C-HIGH", "Control C-MEDIUM", "Control C-LOW"},
		},
		{
			name:        "medium and above",
			threshold:   "medium",
			wantNew:     []string{"C-CRITICAL", "C-MEDIUM", "C-HIGH"},
			wantIncomp:  []string{"C-INCOMPARABLE"},
			wantSARIF:   []string{"C-INCOMPARABLE", "C-CRITICAL", "C-HIGH", "C-MEDIUM"},
			wantGitLab:  []string{"C-INCOMPARABLE", "C-CRITICAL", "C-HIGH", "C-MEDIUM"},
			wantJUnit:   4,
			wantDetails: []string{"Control C-CRITICAL", "Control C-HIGH", "Control C-MEDIUM"},
		},
		{
			name:        "high and above",
			threshold:   "high",
			wantNew:     []string{"C-CRITICAL", "C-HIGH"},
			wantIncomp:  []string{"C-INCOMPARABLE"},
			wantSARIF:   []string{"C-INCOMPARABLE", "C-CRITICAL", "C-HIGH"},
			wantGitLab:  []string{"C-INCOMPARABLE", "C-CRITICAL", "C-HIGH"},
			wantJUnit:   3,
			wantDetails: []string{"Control C-CRITICAL", "Control C-HIGH"},
		},
		{
			name:        "critical only",
			threshold:   "critical",
			wantNew:     []string{"C-CRITICAL"},
			wantIncomp:  []string{},
			wantSARIF:   []string{"C-CRITICAL"},
			wantGitLab:  []string{"C-CRITICAL"},
			wantJUnit:   1,
			wantDetails: []string{"Control C-CRITICAL"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			regressions := Regressions(ciChangeSet(), test.threshold)
			assert.Equal(t, test.wantNew, controlIDs(regressions.New))
			assert.Equal(t, test.wantIncomp, controlIDs(regressions.Incomparable))

			var sarif bytes.Buffer
			require.NoError(t, PrintSARIF(&sarif, ciChangeSet(), test.threshold))
			sarifReport := decodeJSON[diffSARIFReport](t, sarif.Bytes())
			require.Len(t, sarifReport.Runs, 1)
			assert.Equal(t, test.wantSARIF, sarifResultRuleIDs(sarifReport.Runs[0].Results))

			var gitlab bytes.Buffer
			require.NoError(t, PrintGitLabSAST(&gitlab, ciChangeSet(), test.threshold))
			gitLabReport := decodeJSON[diffGitLabReport](t, gitlab.Bytes())
			assert.Equal(t, test.wantGitLab, gitLabVulnerabilityControlIDs(gitLabReport.Vulnerabilities))

			var junit bytes.Buffer
			require.NoError(t, PrintJUnit(&junit, ciChangeSet(), test.threshold))
			junitReport := decodeJUnit(t, junit.Bytes())
			assert.Equal(t, test.wantJUnit, junitReport.Tests)
			assert.Equal(t, test.wantJUnit, junitReport.Failures)

			var markdown bytes.Buffer
			require.NoError(t, PrintMarkdown(&markdown, ciChangeSet(), test.threshold))
			markdownText := markdown.String()
			for _, detail := range test.wantDetails {
				assert.Contains(t, markdownText, detail)
			}
			if test.threshold != "" {
				assert.Contains(t, markdownText, "Severity threshold: "+test.threshold)
			}
		})
	}
}

func TestCIPrinters_ExcludeResolvedAndUnchangedFindings(t *testing.T) {
	cs := ciChangeSet()

	var sarif bytes.Buffer
	require.NoError(t, PrintSARIF(&sarif, cs, ""))
	sarifReport := decodeJSON[diffSARIFReport](t, sarif.Bytes())
	require.Len(t, sarifReport.Runs, 1)
	sarifJSON := sarif.String()
	assert.NotContains(t, sarifJSON, "C-RESOLVED")
	assert.NotContains(t, sarifJSON, "C-UNCHANGED")

	var gitlab bytes.Buffer
	require.NoError(t, PrintGitLabSAST(&gitlab, cs, ""))
	gitlabJSON := gitlab.String()
	assert.NotContains(t, gitlabJSON, "C-RESOLVED")
	assert.NotContains(t, gitlabJSON, "C-UNCHANGED")

	var junit bytes.Buffer
	require.NoError(t, PrintJUnit(&junit, cs, ""))
	junitXML := junit.String()
	assert.NotContains(t, junitXML, "C-RESOLVED")
	assert.NotContains(t, junitXML, "C-UNCHANGED")

	var markdown bytes.Buffer
	require.NoError(t, PrintMarkdown(&markdown, cs, ""))
	markdownText := markdown.String()
	assert.NotContains(t, markdownText, "C-RESOLVED")
	assert.NotContains(t, markdownText, "C-UNCHANGED")
}

func TestPrintSARIF_ResultPropertiesSurviveJSONRoundTrip(t *testing.T) {
	change := ciChange("C-ROUNDTRIP", "apps/v1/default/Deployment/roundtrip", "Medium")
	change.BaseStatus = "absent"
	change.HeadStatus = "failed"
	change.EvidenceResourceID = "apps/v1/default/Pod/roundtrip"
	change.Reason = "base report did not include this control"

	var output bytes.Buffer
	require.NoError(t, PrintSARIF(&output, &ChangeSet{Incomparable: []ControlChange{change}}, ""))

	var raw map[string]any
	require.NoError(t, json.Unmarshal(output.Bytes(), &raw))
	runs := raw["runs"].([]any)
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	result := results[0].(map[string]any)
	properties := result["properties"].(map[string]any)
	fingerprints := result["partialFingerprints"].(map[string]any)

	assert.Equal(t, "incomparable", properties["changeType"])
	assert.Equal(t, "apps/v1/default/Deployment/roundtrip", properties["resourceID"])
	assert.Equal(t, "C-ROUNDTRIP", properties["controlID"])
	assert.Equal(t, "Control C-ROUNDTRIP", properties["controlName"])
	assert.Equal(t, "Medium", properties["severity"])
	assert.Equal(t, "absent", properties["baseStatus"])
	assert.Equal(t, "failed", properties["headStatus"])
	assert.Equal(t, "rule-c-roundtrip", properties["ruleName"])
	assert.Equal(t, "reviewPath", properties["evidenceType"])
	assert.Equal(t, "spec.template.spec.containers[0].securityContext.privileged", properties["evidencePath"])
	assert.Equal(t, "apps/v1/default/Pod/roundtrip", properties["evidenceResourceID"])
	assert.Equal(t, "base report did not include this control", properties["incomparableReason"])
	assert.NotEmpty(t, fingerprints["kubescapeDiffFingerprint"])
}

func TestPrintSARIF_RulesUseHighestSeveritySortedControlMetadata(t *testing.T) {
	first := ciChange("C-DUPLICATE", "apps/v1/default/Deployment/a", "Medium")
	first.ControlName = "First name"
	second := ciChange("C-DUPLICATE", "apps/v1/default/Deployment/b", "Critical")
	second.ControlName = "Second name"

	var output bytes.Buffer
	require.NoError(t, PrintSARIF(&output, &ChangeSet{New: []ControlChange{first, second}}, ""))

	report := decodeJSON[diffSARIFReport](t, output.Bytes())
	require.Len(t, report.Runs, 1)
	require.Len(t, report.Runs[0].Tool.Driver.Rules, 1)
	rule := report.Runs[0].Tool.Driver.Rules[0]
	assert.Equal(t, "C-DUPLICATE", rule.ID)
	assert.Equal(t, "Second name", rule.Name)
	assert.Equal(t, "Second name", rule.ShortDescription.Text)
	assert.Equal(t, "9.0", rule.Properties["security-severity"])
	assert.Equal(t, "Critical", rule.Properties["kubescapeSeverity"])
}

func TestPrintSARIF_ResultOrderingIsStableAcrossRuns(t *testing.T) {
	var first bytes.Buffer
	var second bytes.Buffer

	require.NoError(t, PrintSARIF(&first, ciChangeSet(), ""))
	require.NoError(t, PrintSARIF(&second, ciChangeSet(), ""))

	assert.Equal(t, first.String(), second.String())
}

func TestPrintGitLabSAST_VulnerabilityIDsAreStableAcrossRuns(t *testing.T) {
	var first bytes.Buffer
	var second bytes.Buffer

	require.NoError(t, PrintGitLabSAST(&first, ciChangeSet(), ""))
	require.NoError(t, PrintGitLabSAST(&second, ciChangeSet(), ""))

	firstReport := decodeJSON[diffGitLabReport](t, first.Bytes())
	secondReport := decodeJSON[diffGitLabReport](t, second.Bytes())
	require.Len(t, firstReport.Vulnerabilities, len(secondReport.Vulnerabilities))
	for i := range firstReport.Vulnerabilities {
		assert.Equal(t, firstReport.Vulnerabilities[i].ID, secondReport.Vulnerabilities[i].ID)
	}
}

func TestPrintGitLabSAST_MapsUnknownOrEmptyControlIDToToolURL(t *testing.T) {
	change := ciChange("", "apps/v1/default/Deployment/no-control-id", "Unknown")
	change.ControlName = ""

	var output bytes.Buffer
	require.NoError(t, PrintGitLabSAST(&output, &ChangeSet{New: []ControlChange{change}}, ""))

	report := decodeJSON[diffGitLabReport](t, output.Bytes())
	require.Len(t, report.Vulnerabilities, 1)
	vuln := report.Vulnerabilities[0]
	assert.Equal(t, "Unknown", vuln.Severity)
	require.Len(t, vuln.Identifiers, 1)
	assert.Equal(t, diffToolURI, vuln.Identifiers[0].URL)
	assert.Equal(t, "unknown", vuln.Identifiers[0].Name)
	assert.Equal(t, "unknown", vuln.Identifiers[0].Value)
	assert.Equal(t, "New Kubescape failure: ", vuln.Name)
}

func TestPrintGitLabSAST_ProducesRequiredScannerFields(t *testing.T) {
	var output bytes.Buffer
	require.NoError(t, PrintGitLabSAST(&output, ciChangeSet(), "critical"))

	report := decodeJSON[diffGitLabReport](t, output.Bytes())
	assert.Equal(t, diffScannerID, report.Scan.Analyzer.ID)
	assert.Equal(t, diffScannerID, report.Scan.Scanner.ID)
	assert.Equal(t, diffToolName, report.Scan.Analyzer.Name)
	assert.Equal(t, diffToolName, report.Scan.Scanner.Name)
	assert.Equal(t, diffToolURI, report.Scan.Analyzer.URL)
	assert.Equal(t, diffToolURI, report.Scan.Scanner.URL)
	assert.Equal(t, "diff", report.Scan.Analyzer.Version)
	assert.Equal(t, "diff", report.Scan.Scanner.Version)
	assert.Equal(t, diffGitLabTime, report.Scan.StartTime)
	assert.Equal(t, diffGitLabTime, report.Scan.EndTime)
}

func TestPrintJUnit_XMLEscapesAttributesAndBody(t *testing.T) {
	change := ciChange("C-XML", `apps/v1/default/Deployment/a&b`, "High")
	change.ControlName = `Control "quoted" & angled <name>`
	change.Reason = `reason "quoted" & angled <body>`

	var output bytes.Buffer
	require.NoError(t, PrintJUnit(&output, &ChangeSet{Incomparable: []ControlChange{change}}, ""))

	raw := output.String()
	assert.Contains(t, raw, `Control &#34;quoted&#34; &amp; angled &lt;name&gt;`)
	assert.Contains(t, raw, `reason &#34;quoted&#34; &amp; angled &lt;body&gt;`)

	decoded := decodeJUnit(t, output.Bytes())
	require.Len(t, decoded.Suites, 1)
	require.Len(t, decoded.Suites[0].TestCases, 1)
	assert.Contains(t, decoded.Suites[0].TestCases[0].Name, `Control "quoted" & angled <name>`)
	assert.Contains(t, decoded.Suites[0].TestCases[0].Failure.Contents, `reason "quoted" & angled <body>`)
}

func TestPrintJUnit_ClassnameFallsBackToKubescapeDiffPrefix(t *testing.T) {
	change := ciChange("", "apps/v1/default/Deployment/no-control-id", "High")

	var output bytes.Buffer
	require.NoError(t, PrintJUnit(&output, &ChangeSet{New: []ControlChange{change}}, ""))

	decoded := decodeJUnit(t, output.Bytes())
	require.Len(t, decoded.Suites, 1)
	require.Len(t, decoded.Suites[0].TestCases, 1)
	assert.Equal(t, "kubescape.diff/", decoded.Suites[0].TestCases[0].Classname)
}

func TestPrintMarkdown_WritesWarningsWithoutFindings(t *testing.T) {
	var output bytes.Buffer
	require.NoError(t, PrintMarkdown(&output, &ChangeSet{Warnings: []string{"scope differs"}}, "high"))

	actual := output.String()
	assert.Contains(t, actual, "| Warnings | 1 |")
	assert.Contains(t, actual, "## Warnings")
	assert.Contains(t, actual, "- scope differs")
	assert.Contains(t, actual, "No new or incomparable failures matched the severity threshold.")
}

func TestPrintMarkdown_EmptyThresholdIsRenderedAsAll(t *testing.T) {
	var output bytes.Buffer
	require.NoError(t, PrintMarkdown(&output, &ChangeSet{New: []ControlChange{ciChange("C-HIGH", "resource", "High")}}, ""))

	assert.Contains(t, output.String(), "Severity threshold: all")
}

func TestMarkdownEscape_NormalizesEmptyAndWhitespace(t *testing.T) {
	assert.Equal(t, "-", markdownEscape(""))
	assert.Equal(t, "-", markdownEscape(" \n\t "))
	assert.Equal(t, "a b", markdownEscape("a\nb"))
	assert.Equal(t, `a\\b`, markdownEscape(`a\b`))
	assert.Equal(t, `a\|b`, markdownEscape(`a|b`))
}

func TestJUnitCaseName_UsesOnlyNonEmptyParts(t *testing.T) {
	assert.Equal(t, "Control C-1 / resource / rule=rule-c-1 type=reviewPath path=spec.template.spec.containers[0].securityContext.privileged", junitCaseName(ciChange("C-1", "resource", "High")))
	assert.Equal(t, "resource", junitCaseName(ControlChange{ResourceID: "resource"}))
	assert.Equal(t, "", junitCaseName(ControlChange{}))
}

func TestDiffSolution(t *testing.T) {
	newChange := ciChange("C-HIGH", "resource", "High")
	assert.Equal(t, "Fix the failed control or add a reviewed Kubescape exception if the risk is accepted.", diffSolution("new", newChange))

	incomparable := newChange
	incomparable.Reason = "scope changed"
	assert.Equal(t, "Review scan coverage and scope before treating this finding as resolved: scope changed", diffSolution("incomparable", incomparable))

	incomparable.Reason = ""
	assert.Equal(t, "Review scan coverage and scope before treating this finding as resolved.", diffSolution("incomparable", incomparable))
}

func TestNonEmpty_TrimsWithoutMutatingValues(t *testing.T) {
	input := []string{"a", " ", "\t", "b"}

	got := nonEmpty(input)

	assert.Equal(t, []string{"a", "b"}, got)
}

func TestCompareChange_OrdersBySeverityThenIdentity(t *testing.T) {
	critical := ciChange("C-CRITICAL", "resource", "Critical")
	high := ciChange("C-HIGH", "resource", "High")
	mediumA := ciChange("C-MEDIUM-A", "resource-a", "Medium")
	mediumB := ciChange("C-MEDIUM-B", "resource-b", "Medium")

	assert.Less(t, compareChange(critical, high), 0)
	assert.Greater(t, compareChange(high, critical), 0)
	assert.Less(t, compareChange(mediumA, mediumB), 0)
	assert.Equal(t, 0, compareChange(mediumA, mediumA))
}

func TestCIOutputContainsNoResolvedOrUnchangedForEachFormat(t *testing.T) {
	formats := []struct {
		name  string
		print func(*bytes.Buffer) error
	}{
		{"markdown", func(buf *bytes.Buffer) error { return PrintMarkdown(buf, ciChangeSet(), "") }},
		{"junit", func(buf *bytes.Buffer) error { return PrintJUnit(buf, ciChangeSet(), "") }},
		{"sarif", func(buf *bytes.Buffer) error { return PrintSARIF(buf, ciChangeSet(), "") }},
		{"gitlab", func(buf *bytes.Buffer) error { return PrintGitLabSAST(buf, ciChangeSet(), "") }},
	}

	for _, format := range formats {
		t.Run(format.name, func(t *testing.T) {
			var output bytes.Buffer
			require.NoError(t, format.print(&output))
			assert.NotContains(t, output.String(), "apps/v1/default/Deployment/resolved")
			assert.NotContains(t, output.String(), "apps/v1/default/Deployment/unchanged")
		})
	}
}

func TestCIOutputRoundTripsLargeRegressionSet(t *testing.T) {
	cs := &ChangeSet{}
	for i := 0; i < 50; i++ {
		severity := "Low"
		if i%2 == 0 {
			severity = "High"
		}
		change := ciChange(fmt.Sprintf("C-%04d", i), fmt.Sprintf("apps/v1/ns/Deployment/workload-%02d", i), severity)
		if i%5 == 0 {
			change.Reason = "coverage changed"
			cs.Incomparable = append(cs.Incomparable, change)
		} else {
			cs.New = append(cs.New, change)
		}
	}

	var sarif bytes.Buffer
	require.NoError(t, PrintSARIF(&sarif, cs, "high"))
	sarifReport := decodeJSON[diffSARIFReport](t, sarif.Bytes())
	require.Len(t, sarifReport.Runs, 1)
	assert.Len(t, sarifReport.Runs[0].Results, 25)

	var gitlab bytes.Buffer
	require.NoError(t, PrintGitLabSAST(&gitlab, cs, "high"))
	gitlabReport := decodeJSON[diffGitLabReport](t, gitlab.Bytes())
	assert.Len(t, gitlabReport.Vulnerabilities, 25)

	var junit bytes.Buffer
	require.NoError(t, PrintJUnit(&junit, cs, "high"))
	junitReport := decodeJUnit(t, junit.Bytes())
	assert.Equal(t, 25, junitReport.Tests)
	assert.Equal(t, 25, junitReport.Failures)

	var markdown bytes.Buffer
	require.NoError(t, PrintMarkdown(&markdown, cs, "high"))
	assert.Contains(t, markdown.String(), "| New | 20 |")
	assert.Contains(t, markdown.String(), "| Incomparable | 5 |")
}

func TestSARIFRulesRemainSortedWhenResultsAreNot(t *testing.T) {
	cs := &ChangeSet{New: []ControlChange{
		ciChange("C-Z", "resource-z", "High"),
		ciChange("C-A", "resource-a", "High"),
		ciChange("C-M", "resource-m", "High"),
	}}

	var output bytes.Buffer
	require.NoError(t, PrintSARIF(&output, cs, ""))

	report := decodeJSON[diffSARIFReport](t, output.Bytes())
	require.Len(t, report.Runs, 1)
	assert.Equal(t, []string{"C-A", "C-M", "C-Z"}, sarifRuleIDs(report.Runs[0].Tool.Driver.Rules))
}

func TestGitLabVulnerabilitiesPreserveSortedFindingOrder(t *testing.T) {
	cs := &ChangeSet{New: []ControlChange{
		ciChange("C-LOW", "resource-low", "Low"),
		ciChange("C-HIGH", "resource-high", "High"),
		ciChange("C-CRITICAL", "resource-critical", "Critical"),
	}}

	var output bytes.Buffer
	require.NoError(t, PrintGitLabSAST(&output, cs, ""))

	report := decodeJSON[diffGitLabReport](t, output.Bytes())
	assert.Equal(t, []string{"C-CRITICAL", "C-HIGH", "C-LOW"}, gitLabVulnerabilityControlIDs(report.Vulnerabilities))
}

func sarifResultRuleIDs(results []diffSARIFResult) []string {
	ids := make([]string, 0, len(results))
	for _, result := range results {
		ids = append(ids, result.RuleID)
	}
	return ids
}

func gitLabVulnerabilityControlIDs(vulns []diffGitLabVuln) []string {
	ids := make([]string, 0, len(vulns))
	for _, vuln := range vulns {
		if len(vuln.Identifiers) == 0 {
			ids = append(ids, "")
			continue
		}
		ids = append(ids, vuln.Identifiers[0].Value)
	}
	return ids
}
