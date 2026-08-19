package diff

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	diffToolName    = "Kubescape"
	diffToolURI     = "https://kubescape.io"
	diffGitLabVer   = "15.2.4"
	diffGitLabTime  = "1970-01-01T00:00:00"
	diffScannerID   = "kubescape"
	diffScanType    = "sast"
	diffControlType = "kubescape_control_id"
)

// RegressionSet is the machine-reportable subset of a ChangeSet. Human output
// can show all buckets, but CI ingestion should focus on items that should keep
// a pull request red: conclusive new failures and failures that are unsafe to
// classify as resolved/new because scan coverage or scope changed.
type RegressionSet struct {
	New          []ControlChange `json:"new"`
	Incomparable []ControlChange `json:"incomparable,omitempty"`
	Warnings     []string        `json:"warnings,omitempty"`
}

// Regressions returns the new and incomparable diff findings after applying the
// same severity threshold used by --fail-on-new. It clones slices so serializers
// cannot accidentally mutate the full ChangeSet.
func Regressions(cs *ChangeSet, threshold string) RegressionSet {
	if cs == nil {
		return RegressionSet{}
	}
	return RegressionSet{
		New:          cloneChanges(FilterBySeverity(cs.New, threshold)),
		Incomparable: cloneChanges(FilterBySeverity(cs.Incomparable, threshold)),
		Warnings:     append([]string(nil), cs.Warnings...),
	}
}

func cloneChanges(changes []ControlChange) []ControlChange {
	out := make([]ControlChange, len(changes))
	copy(out, changes)
	return out
}

func (r RegressionSet) count() int {
	return len(r.New) + len(r.Incomparable)
}

func (r RegressionSet) all() []ciFinding {
	findings := make([]ciFinding, 0, r.count())
	for _, change := range r.New {
		findings = append(findings, ciFinding{Change: change, Kind: "new"})
	}
	for _, change := range r.Incomparable {
		findings = append(findings, ciFinding{Change: change, Kind: "incomparable"})
	}
	sort.SliceStable(findings, func(i, j int) bool {
		left, right := findings[i], findings[j]
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		return compareChange(left.Change, right.Change) < 0
	})
	return findings
}

type ciFinding struct {
	Change ControlChange
	Kind   string
}

func compareChange(left, right ControlChange) int {
	if leftRank, rightRank := severityRank(left.Severity), severityRank(right.Severity); leftRank != rightRank {
		return rightRank - leftRank
	}
	for _, pair := range [][2]string{
		{left.ResourceID, right.ResourceID},
		{left.ControlID, right.ControlID},
		{left.RuleName, right.RuleName},
		{left.EvidenceType, right.EvidenceType},
		{left.Path, right.Path},
		{left.EvidenceResourceID, right.EvidenceResourceID},
		{left.Reason, right.Reason},
	} {
		if pair[0] != pair[1] {
			return strings.Compare(pair[0], pair[1])
		}
	}
	return 0
}

// PrintMarkdown writes a compact PR-friendly regression report. It intentionally
// omits resolved and unchanged items because those are useful in local review
// but noisy in a pull request comment.
func PrintMarkdown(w io.Writer, cs *ChangeSet, threshold string) error {
	regressions := Regressions(cs, threshold)
	ew := errWriter{w: w}
	ew.printf("# Kubescape Diff Regressions\n\n")
	ew.printf("| Bucket | Count |\n")
	ew.printf("|---|---:|\n")
	ew.printf("| New | %d |\n", len(regressions.New))
	ew.printf("| Incomparable | %d |\n", len(regressions.Incomparable))
	ew.printf("| Warnings | %d |\n\n", len(regressions.Warnings))

	if threshold == "" {
		ew.printf("Severity threshold: all\n\n")
	} else {
		ew.printf("Severity threshold: %s\n\n", threshold)
	}

	if len(regressions.Warnings) > 0 {
		ew.printf("## Warnings\n\n")
		for _, warning := range regressions.Warnings {
			ew.printf("- %s\n", markdownEscape(warning))
		}
		ew.printf("\n")
	}

	writeMarkdownFindings(&ew, "New Failures", regressions.New)
	writeMarkdownFindings(&ew, "Incomparable Failures", regressions.Incomparable)
	if regressions.count() == 0 {
		ew.printf("No new or incomparable failures matched the severity threshold.\n")
	}
	return ew.err
}

type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, args ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, args...)
}

func writeMarkdownFindings(ew *errWriter, title string, changes []ControlChange) {
	if len(changes) == 0 {
		return
	}
	ew.printf("## %s\n\n", title)
	ew.printf("| Severity | Control | Resource | Evidence | Reason |\n")
	ew.printf("|---|---|---|---|---|\n")
	for _, change := range changes {
		ew.printf("| %s | %s | %s | %s | %s |\n",
			markdownEscape(change.Severity),
			markdownEscape(fmt.Sprintf("%s (%s)", change.ControlName, change.ControlID)),
			markdownEscape(change.ResourceID),
			markdownEscape(evidenceLabel(change)),
			markdownEscape(change.Reason),
		)
	}
	ew.printf("\n")
}

func markdownEscape(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}

// PrintJUnit writes new and incomparable diff findings as failing test cases,
// which lets CI systems annotate pull requests without re-reporting unchanged
// posture failures.
func PrintJUnit(w io.Writer, cs *ChangeSet, threshold string) error {
	regressions := Regressions(cs, threshold)
	suites := diffJUnitSuites{
		Name:     "Kubescape Diff",
		Tests:    regressions.count(),
		Failures: regressions.count(),
		Suites: []diffJUnitSuite{
			diffJUnitBucketSuite(0, "new", regressions.New),
			diffJUnitBucketSuite(1, "incomparable", regressions.Incomparable),
		},
	}
	suites.Suites = nonEmptyJUnitSuites(suites.Suites)
	data, err := xml.MarshalIndent(suites, "", "  ")
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(xml.Header)); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

type diffJUnitSuites struct {
	XMLName  xml.Name         `xml:"testsuites"`
	Name     string           `xml:"name,attr,omitempty"`
	Tests    int              `xml:"tests,attr"`
	Failures int              `xml:"failures,attr"`
	Errors   int              `xml:"errors,attr"`
	Suites   []diffJUnitSuite `xml:"testsuite"`
}

type diffJUnitSuite struct {
	XMLName   xml.Name            `xml:"testsuite"`
	ID        int                 `xml:"id,attr"`
	Name      string              `xml:"name,attr"`
	Tests     int                 `xml:"tests,attr"`
	Failures  int                 `xml:"failures,attr"`
	TestCases []diffJUnitTestCase `xml:"testcase"`
}

type diffJUnitTestCase struct {
	XMLName   xml.Name          `xml:"testcase"`
	Classname string            `xml:"classname,attr"`
	Name      string            `xml:"name,attr"`
	Failure   *diffJUnitFailure `xml:"failure,omitempty"`
}

type diffJUnitFailure struct {
	Message  string `xml:"message,attr"`
	Type     string `xml:"type,attr"`
	Contents string `xml:",chardata"`
}

func diffJUnitBucketSuite(id int, name string, changes []ControlChange) diffJUnitSuite {
	testCases := make([]diffJUnitTestCase, 0, len(changes))
	for _, change := range changes {
		testCases = append(testCases, diffJUnitTestCase{
			Classname: "kubescape.diff/" + change.ControlID,
			Name:      junitCaseName(change),
			Failure: &diffJUnitFailure{
				Type:     name,
				Message:  findingTitle(name, change),
				Contents: findingDetails(change),
			},
		})
	}
	return diffJUnitSuite{
		ID:        id,
		Name:      "kubescape diff " + name,
		Tests:     len(testCases),
		Failures:  len(testCases),
		TestCases: testCases,
	}
}

func nonEmptyJUnitSuites(suites []diffJUnitSuite) []diffJUnitSuite {
	out := suites[:0]
	for _, suite := range suites {
		if suite.Tests > 0 {
			out = append(out, suite)
		}
	}
	return out
}

func junitCaseName(change ControlChange) string {
	parts := []string{change.ControlName, change.ResourceID}
	if evidence := evidenceLabel(change); evidence != "" {
		parts = append(parts, evidence)
	}
	return strings.Join(nonEmpty(parts), " / ")
}

// PrintSARIF writes a SARIF 2.1.0 report for new/incomparable diff findings.
// Locations use the Kubescape resource ID as the artifact URI because diff
// reports are computed from JSON scan reports and do not always retain a source
// manifest path.
func PrintSARIF(w io.Writer, cs *ChangeSet, threshold string) error {
	regressions := Regressions(cs, threshold)
	report := diffSARIFReport{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []diffSARIFRun{{
			Tool: diffSARIFTool{Driver: diffSARIFDriver{
				Name:           diffToolName,
				InformationURI: diffToolURI,
				Rules:          sarifRules(regressions.all()),
			}},
			Results: sarifResults(regressions.all()),
		}},
	}
	return encodeJSON(w, report)
}

type diffSARIFReport struct {
	Version string         `json:"version"`
	Schema  string         `json:"$schema,omitempty"`
	Runs    []diffSARIFRun `json:"runs"`
}

type diffSARIFRun struct {
	Tool    diffSARIFTool     `json:"tool"`
	Results []diffSARIFResult `json:"results"`
}

type diffSARIFTool struct {
	Driver diffSARIFDriver `json:"driver"`
}

type diffSARIFDriver struct {
	Name           string          `json:"name"`
	InformationURI string          `json:"informationUri,omitempty"`
	Rules          []diffSARIFRule `json:"rules,omitempty"`
}

type diffSARIFRule struct {
	ID                   string                   `json:"id"`
	Name                 string                   `json:"name,omitempty"`
	ShortDescription     diffSARIFMessage         `json:"shortDescription,omitempty"`
	DefaultConfiguration diffSARIFConfiguration   `json:"defaultConfiguration,omitempty"`
	Properties           map[string]string        `json:"properties,omitempty"`
	Help                 *diffSARIFMessage        `json:"help,omitempty"`
	FullDescription      *diffSARIFMessage        `json:"fullDescription,omitempty"`
	Relationships        []map[string]interface{} `json:"relationships,omitempty"`
}

type diffSARIFConfiguration struct {
	Level string `json:"level,omitempty"`
}

type diffSARIFResult struct {
	RuleID       string              `json:"ruleId"`
	Level        string              `json:"level,omitempty"`
	Message      diffSARIFMessage    `json:"message"`
	Locations    []diffSARIFLocation `json:"locations,omitempty"`
	Properties   map[string]string   `json:"properties,omitempty"`
	Fingerprints map[string]string   `json:"partialFingerprints,omitempty"`
}

type diffSARIFMessage struct {
	Text string `json:"text,omitempty"`
}

type diffSARIFLocation struct {
	PhysicalLocation diffSARIFPhysicalLocation `json:"physicalLocation"`
}

type diffSARIFPhysicalLocation struct {
	ArtifactLocation diffSARIFArtifactLocation `json:"artifactLocation"`
	Region           diffSARIFRegion           `json:"region,omitempty"`
}

type diffSARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type diffSARIFRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

func sarifRules(findings []ciFinding) []diffSARIFRule {
	byID := make(map[string]ControlChange)
	for _, finding := range findings {
		if _, exists := byID[finding.Change.ControlID]; !exists {
			byID[finding.Change.ControlID] = finding.Change
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rules := make([]diffSARIFRule, 0, len(ids))
	for _, id := range ids {
		change := byID[id]
		rules = append(rules, diffSARIFRule{
			ID:               change.ControlID,
			Name:             change.ControlName,
			ShortDescription: diffSARIFMessage{Text: change.ControlName},
			DefaultConfiguration: diffSARIFConfiguration{
				Level: sarifLevel(change.Severity),
			},
			Properties: map[string]string{
				"security-severity": sarifSecuritySeverity(change.Severity),
				"kubescapeSeverity": change.Severity,
			},
		})
	}
	return rules
}

func sarifResults(findings []ciFinding) []diffSARIFResult {
	results := make([]diffSARIFResult, 0, len(findings))
	for _, finding := range findings {
		change := finding.Change
		results = append(results, diffSARIFResult{
			RuleID:  change.ControlID,
			Level:   sarifLevel(change.Severity),
			Message: diffSARIFMessage{Text: findingTitle(finding.Kind, change) + "\n\n" + findingDetails(change)},
			Locations: []diffSARIFLocation{{
				PhysicalLocation: diffSARIFPhysicalLocation{
					ArtifactLocation: diffSARIFArtifactLocation{URI: change.ResourceID},
					Region:           diffSARIFRegion{StartLine: 1},
				},
			}},
			Properties: map[string]string{
				"changeType":         finding.Kind,
				"resourceID":         change.ResourceID,
				"controlID":          change.ControlID,
				"controlName":        change.ControlName,
				"severity":           change.Severity,
				"baseStatus":         change.BaseStatus,
				"headStatus":         change.HeadStatus,
				"ruleName":           change.RuleName,
				"evidenceType":       change.EvidenceType,
				"evidencePath":       change.Path,
				"evidenceResourceID": change.EvidenceResourceID,
				"incomparableReason": change.Reason,
			},
			Fingerprints: map[string]string{
				"kubescapeDiffFingerprint": stableFindingID(finding.Kind, change),
			},
		})
	}
	return results
}

// PrintGitLabSAST writes a GitLab SAST-compatible report containing only new
// and incomparable diff findings.
func PrintGitLabSAST(w io.Writer, cs *ChangeSet, threshold string) error {
	regressions := Regressions(cs, threshold)
	scanner := diffGitLabScanner{
		ID:      diffScannerID,
		Name:    diffToolName,
		URL:     diffToolURI,
		Version: "diff",
		Vendor:  diffGitLabVendor{Name: diffToolName},
	}
	report := diffGitLabReport{
		Version: diffGitLabVer,
		Scan: diffGitLabScan{
			Analyzer:  scanner,
			Scanner:   scanner,
			Type:      diffScanType,
			StartTime: diffGitLabTime,
			EndTime:   diffGitLabTime,
			Status:    "success",
		},
		Vulnerabilities: gitLabVulnerabilities(regressions.all()),
	}
	return encodeJSON(w, report)
}

type diffGitLabReport struct {
	Version         string           `json:"version"`
	Scan            diffGitLabScan   `json:"scan"`
	Vulnerabilities []diffGitLabVuln `json:"vulnerabilities"`
}

type diffGitLabScan struct {
	Analyzer  diffGitLabScanner `json:"analyzer"`
	Scanner   diffGitLabScanner `json:"scanner"`
	Type      string            `json:"type"`
	StartTime string            `json:"start_time"`
	EndTime   string            `json:"end_time"`
	Status    string            `json:"status"`
}

type diffGitLabScanner struct {
	ID      string           `json:"id"`
	Name    string           `json:"name"`
	URL     string           `json:"url,omitempty"`
	Version string           `json:"version"`
	Vendor  diffGitLabVendor `json:"vendor"`
}

type diffGitLabVendor struct {
	Name string `json:"name"`
}

type diffGitLabVuln struct {
	ID          string                 `json:"id"`
	Category    string                 `json:"category"`
	Name        string                 `json:"name"`
	Message     string                 `json:"message"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"`
	Scanner     diffGitLabScannerRef   `json:"scanner"`
	Location    diffGitLabLocation     `json:"location"`
	Identifiers []diffGitLabIdentifier `json:"identifiers"`
	Solution    string                 `json:"solution,omitempty"`
}

type diffGitLabScannerRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type diffGitLabLocation struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
}

type diffGitLabIdentifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	URL   string `json:"url,omitempty"`
}

func gitLabVulnerabilities(findings []ciFinding) []diffGitLabVuln {
	vulns := make([]diffGitLabVuln, 0, len(findings))
	for _, finding := range findings {
		change := finding.Change
		vulns = append(vulns, diffGitLabVuln{
			ID:          stableFindingID(finding.Kind, change),
			Category:    diffScanType,
			Name:        findingTitle(finding.Kind, change),
			Message:     findingTitle(finding.Kind, change),
			Description: findingDetails(change),
			Severity:    gitLabSeverity(change.Severity),
			Scanner:     diffGitLabScannerRef{ID: diffScannerID, Name: diffToolName},
			Location:    diffGitLabLocation{File: change.ResourceID, StartLine: 1},
			Identifiers: []diffGitLabIdentifier{{
				Type:  diffControlType,
				Name:  emptyAsUnknown(change.ControlID),
				Value: emptyAsUnknown(change.ControlID),
				URL:   controlDocsURL(change.ControlID),
			}},
			Solution: diffSolution(finding.Kind, change),
		})
	}
	return vulns
}

func encodeJSON(w io.Writer, value any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

func findingTitle(kind string, change ControlChange) string {
	prefix := "New Kubescape failure"
	if kind == "incomparable" {
		prefix = "Incomparable Kubescape failure"
	}
	if change.ControlName != "" {
		return fmt.Sprintf("%s: %s (%s)", prefix, change.ControlName, change.ControlID)
	}
	return fmt.Sprintf("%s: %s", prefix, change.ControlID)
}

func findingDetails(change ControlChange) string {
	lines := []string{
		"Resource: " + change.ResourceID,
		"Control: " + strings.TrimSpace(change.ControlName+" ("+change.ControlID+")"),
		"Severity: " + emptyAsUnknown(change.Severity),
		"Base status: " + emptyAsUnknown(change.BaseStatus),
		"Head status: " + emptyAsUnknown(change.HeadStatus),
	}
	if change.RuleName != "" {
		lines = append(lines, "Rule: "+change.RuleName)
	}
	if evidence := evidenceLabel(change); evidence != "" {
		lines = append(lines, "Evidence: "+evidence)
	}
	if change.EvidenceResourceID != "" && change.EvidenceResourceID != change.ResourceID {
		lines = append(lines, "Evidence resource: "+change.EvidenceResourceID)
	}
	if change.Reason != "" {
		lines = append(lines, "Reason: "+change.Reason)
	}
	return strings.Join(lines, "\n")
}

func evidenceLabel(change ControlChange) string {
	parts := []string{}
	if change.RuleName != "" {
		parts = append(parts, "rule="+change.RuleName)
	}
	if change.EvidenceType != "" && change.EvidenceType != evidenceTypeControl {
		parts = append(parts, "type="+change.EvidenceType)
	}
	if change.Path != "" {
		parts = append(parts, "path="+change.Path)
	}
	return strings.Join(parts, " ")
}

func diffSolution(kind string, change ControlChange) string {
	if kind == "incomparable" {
		if change.Reason != "" {
			return "Review scan coverage and scope before treating this finding as resolved: " + change.Reason
		}
		return "Review scan coverage and scope before treating this finding as resolved."
	}
	return "Fix the failed control or add a reviewed Kubescape exception if the risk is accepted."
}

func emptyAsUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}

func nonEmpty(values []string) []string {
	out := values[:0]
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}

func stableFindingID(kind string, change ControlChange) string {
	hash := sha256.Sum256([]byte(strings.Join([]string{
		kind,
		change.ResourceID,
		change.ControlID,
		change.RuleName,
		change.EvidenceType,
		change.Path,
		change.EvidenceResourceID,
		change.Reason,
	}, "\x00")))
	return "kubescape-diff-" + hex.EncodeToString(hash[:])[:32]
}

func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func sarifSecuritySeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "9.0"
	case "high":
		return "7.0"
	case "medium":
		return "4.0"
	case "low":
		return "1.0"
	default:
		return "0.0"
	}
}

func gitLabSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	case "negligible":
		return "Info"
	default:
		return "Unknown"
	}
}

func controlDocsURL(controlID string) string {
	if strings.TrimSpace(controlID) == "" {
		return diffToolURI
	}
	return "https://hub.armosec.io/docs/" + strings.TrimSpace(controlID)
}
