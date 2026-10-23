package printer

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHtmlPrinter(t *testing.T) {
	hp := NewHtmlPrinter(false)
	assert.NotNil(t, hp)
	assert.Nil(t, hp.writer)
}

func TestSetWriter_Html(t *testing.T) {
	tests := []struct {
		name       string
		outputFile string
		expected   string
	}{
		{
			name:       "Output file name doesn't contain any extension",
			outputFile: "customFilename",
			expected:   "customFilename.html",
		},
		{
			name:       "Output file name already contains .html",
			outputFile: "customFilename.html",
			expected:   "customFilename.html",
		},
		{
			// Regression for issue-6: empty --output must NOT fall through to
			// stdout — default to ./report.html instead.
			name:       "Output file name is empty defaults to report.html",
			outputFile: "",
			expected:   "report.html",
		},
		{
			name:       "Whitespace-only output file is treated as empty",
			outputFile: "   ",
			expected:   "report.html",
		},
		{
			name:       "Surrounding whitespace is trimmed",
			outputFile: "  myfile  ",
			expected:   "myfile.html",
		},
	}

	ctx := context.Background()

	tmp := t.TempDir()
	origWd, err := os.Getwd()
	assert.NoError(t, err)
	assert.NoError(t, os.Chdir(tmp))
	t.Cleanup(func() { _ = os.Chdir(origWd) })

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hp := NewHtmlPrinter(false)
			hp.SetWriter(ctx, tt.outputFile)
			t.Cleanup(func() {
				_ = hp.writer.Close()
			})
			assert.Equal(t, tt.expected, hp.writer.Name())
			assert.NotEqual(t, "/dev/stdout", hp.writer.Name(),
				"HTML printer must never write to stdout")
		})
	}
}

func TestBuildResourceControlResult_AnnotatesInitAndEphemeralContainerNames(t *testing.T) {
	control := &reportsummary.ControlSummary{
		ControlID:   "C-0057",
		Name:        "Privileged container",
		ScoreFactor: 8.0,
	}
	ac := makeControlWithPaths(privilegedInitAndEphemeralPaths(), nil)
	ac.ControlID = "C-0057"
	ac.Name = "Privileged container"

	got := buildResourceControlResult(*ac, control, privilegedInitAndEphemeralPod(), false)
	require.Equal(t, privilegedInitAndEphemeralNamedPaths(), got.FailedPaths)
}

// TestBuildResourceControlResult_RedactsSecretFixPathValueUnlessShowSecrets
// is a regression test: the HTML report's resource table must redact a
// Secret's plaintext fix-path value by default, matching the terminal
// pretty-printer, and only reveal it when the caller explicitly opts in via
// --show-secrets.
func TestBuildResourceControlResult_RedactsSecretFixPathValueUnlessShowSecrets(t *testing.T) {
	control := &reportsummary.ControlSummary{
		ControlID:   "C-0012",
		Name:        "Credentials in env var",
		ScoreFactor: 8.0,
	}
	resource := &mockResource{kind: "Secret", obj: map[string]any{}}
	ac := resourcesresults.ResourceAssociatedControl{
		ControlID: "C-0012",
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
			{Paths: []armotypes.PosturePaths{
				{FixPath: armotypes.FixPath{Path: "data.password", Value: "s3cr3t-plaintext-password"}},
			}},
		},
	}

	redacted := buildResourceControlResult(ac, control, resource, false)
	redactedJoined := strings.Join(redacted.FailedPaths, " ")
	assert.NotContains(t, redactedJoined, "s3cr3t-plaintext-password")
	assert.Contains(t, redactedJoined, "[redacted]")

	revealed := buildResourceControlResult(ac, control, resource, true)
	assert.Contains(t, strings.Join(revealed.FailedPaths, " "), "s3cr3t-plaintext-password")
}

func TestBuildResourceControlResultTable_MissingControl(t *testing.T) {
	ac := resourcesresults.ResourceAssociatedControl{
		ControlID: "C-MISSING",
		Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
	}

	summaryDetails := &reportsummary.SummaryDetails{
		Controls: reportsummary.ControlSummaries{},
	}

	assert.NotPanics(t, func() {
		results := buildResourceControlResultTable([]resourcesresults.ResourceAssociatedControl{ac}, summaryDetails, nil, false)
		assert.Empty(t, results)
	})
}

func TestBuildResourceTableView_SkipsMissingResource(t *testing.T) {
	session := cautils.NewOPASessionObjMock()
	session.ResourcesResult = map[string]resourcesresults.Result{
		"r-1": {
			ResourceID: "r-1",
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				{
					ControlID: "C-0001",
					Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
				},
			},
		},
	}
	// Do not populate session.AllResources["r-1"]

	view := buildResourceTableView(session, false)
	assert.Empty(t, view, "missing resource should be skipped, not included with nil")
}

// Regression for issue-3328: the HTML report's logo previously loaded from
// raw.githubusercontent.com at view time, so it silently broke for anyone
// viewing an offline scan report without network access, and leaked the
// viewer's IP/UA to GitHub on every view. The logo must be embedded and
// inlined as a data URI instead.
func TestHtmlPrinter_ActionPrint_LogoIsEmbeddedNotFetchedFromNetwork(t *testing.T) {
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "report.html")

	hp := NewHtmlPrinter(false)
	assert.NoError(t, hp.SetWriter(ctx, out))

	session := cautils.NewOPASessionObjMock()
	assert.NoError(t, hp.ActionPrint(ctx, session, nil))
	assert.NoError(t, hp.CloseWriter())

	content, err := os.ReadFile(out)
	assert.NoError(t, err)
	htmlContent := string(content)

	assert.NotContains(t, htmlContent, "raw.githubusercontent.com",
		"HTML report must not depend on fetching the logo from GitHub at view time")
	assert.Contains(t, htmlContent, `<img class="logo" src="data:image/png;base64,`,
		"HTML report must inline the logo as an embedded data URI")
}

func TestHtmlPrinter_ActionPrint_RiskScoreRounding(t *testing.T) {
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "report.html")

	hp := NewHtmlPrinter(false)
	hp.SetWriter(ctx, out)

	// Fixture counters (FailedResources: 2, AllResources: 100) are intentionally
	// distinct from the expected risk score (1) so no other numeric cell renders 0 or 1.
	session := cautils.NewOPASessionObjMock()
	session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{
		"C-0001": reportsummary.ControlSummary{
			ControlID:   "C-0001",
			Name:        "Test Fractional Risk Control",
			Score:       0.4,
			ScoreFactor: 1.0,
			StatusCounters: reportsummary.StatusCounters{
				FailedResources: 2,
				PassedResources: 98,
			},
		},
	}

	hp.ActionPrint(ctx, session, nil)
	hp.CloseWriter()

	content, err := os.ReadFile(out)
	assert.NoError(t, err)
	htmlContent := string(content)

	// Fractional risk score 0.4% must round to 1% display, not 0%
	assert.Contains(t, htmlContent, `<td class="controlRiskCell numericCell">1</td>`)
	assert.NotContains(t, htmlContent, `<td class="controlRiskCell numericCell">0</td>`)
}

func TestHtmlPrinter_ActionPrint_CombinedPostureAndImageScan(t *testing.T) {
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "report.html")

	hp := NewHtmlPrinter(false)
	hp.SetWriter(ctx, out)

	session := cautils.NewOPASessionObjMock()
	imageScanData := []cautils.ImageScanData{
		{
			Image: "registry.example.com/combined-html:v1",
		},
	}

	assert.NoError(t, hp.ActionPrint(ctx, session, imageScanData))
	assert.NoError(t, hp.CloseWriter())

	content, err := os.ReadFile(out)
	assert.NoError(t, err)
	htmlContent := string(content)

	assert.Contains(t, htmlContent, "<h1>Kubescape Scan Report</h1>")
	assert.Contains(t, htmlContent, "<h2>Images scanned:</h2>")
	assert.Contains(t, htmlContent, "registry.example.com/combined-html:v1")
}

func TestHtmlPrinter_ActionPrint_ImageScanShowsKEVAndEPSS(t *testing.T) {
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "report.html")

	hp := NewHtmlPrinter(false)
	require.NoError(t, hp.SetWriter(ctx, out))

	imageScanData := []cautils.ImageScanData{
		{
			Image: "nginx:1.17.0",
			Matches: match.NewMatches(
				mdImageMatch("CVE-2019-0001", "Critical", "openssl", "1.0.0", vulnerability.FixStateNotFixed),
				mdWithExploitData(mdImageMatch("CVE-2020-15999", "Medium", "zlib1g", "1.2.11", vulnerability.FixStateNotFixed), true, 0.63894, 0.99215),
			),
		},
	}

	require.NoError(t, hp.ActionPrint(ctx, nil, imageScanData))
	require.NoError(t, hp.CloseWriter())

	content, err := os.ReadFile(out)
	require.NoError(t, err)
	htmlContent := string(content)

	assert.Contains(t, htmlContent, `<th class="imageKEVCell">KEV</th>`)
	assert.Contains(t, htmlContent, `<th class="imageEPSSCell numericCell">EPSS</th>`)
	assert.Contains(t, htmlContent, `<td class="imageKEVCell">yes</td>`)
	assert.Contains(t, htmlContent, `<td class="imageEPSSCell numericCell">63.9% (99th)</td>`)
	assert.Contains(t, htmlContent, `<td class="imageEPSSCell numericCell">N/A</td>`)

	kev := strings.Index(htmlContent, "CVE-2020-15999")
	critical := strings.Index(htmlContent, "CVE-2019-0001")
	require.NotEqual(t, -1, kev)
	require.NotEqual(t, -1, critical)
	assert.Less(t, kev, critical, "KEV findings must be listed before higher-severity ones")
}

// The report table uses table-layout: fixed, so a column without a width, or
// widths summing past 100%, collapses to zero width in the browser.
func TestHtmlReportTemplate_ImageTableColumnWidths(t *testing.T) {
	head := reportTemplate[strings.Index(reportTemplate, `<table class="imageTable">`):]
	head = head[:strings.Index(head, "</thead>")]
	headers := regexp.MustCompile(`<th class="(image\w+Cell)[^"]*">`).FindAllStringSubmatch(head, -1)
	require.Len(t, headers, strings.Count(head, "<th>")+strings.Count(head, "<th "), "every image table header needs an image*Cell width class")
	require.Len(t, headers, 7)

	total := 0
	for _, h := range headers {
		width := regexp.MustCompile(`\.` + h[1] + ` \{\s*width: (\d+)%;`).FindStringSubmatch(reportTemplate)
		require.NotNil(t, width, "no width rule for .%s", h[1])
		w, err := strconv.Atoi(width[1])
		require.NoError(t, err)
		assert.Positive(t, w, ".%s", h[1])
		total += w
	}
	assert.Equal(t, 100, total, "image table column widths must sum to 100%%")
}

func TestHtmlPrinter_ActionPrint_CoverageSectionPresent(t *testing.T) {
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "report.html")

	hp := NewHtmlPrinter(false)
	hp.SetWriter(ctx, out)

	session := cautils.NewOPASessionObjMock()
	session.ScanCoverage = cautils.ScanCoverage{
		CoverageScore:     85.0,
		EvaluatedControls: 17,
		TotalControls:     20,
		Degraded:          true,
		NotEvaluatedControls: []cautils.NotEvaluatedControl{
			{
				ControlID:   "C-0099",
				MissingGVRs: []string{"apps/v1/daemonsets"},
			},
		},
	}

	assert.NoError(t, hp.ActionPrint(ctx, session, nil))
	assert.NoError(t, hp.CloseWriter())

	content, err := os.ReadFile(out)
	assert.NoError(t, err)
	htmlContent := string(content)

	assert.Contains(t, htmlContent, "<h2>Scan Coverage</h2>")
	assert.Contains(t, htmlContent, "Coverage Score:</strong> 85% ⚠️ Degraded")
	assert.Contains(t, htmlContent, "Evaluated 17 of 20 controls")
	assert.Contains(t, htmlContent, "<td>C-0099</td>")
	assert.Contains(t, htmlContent, "<td>missing: apps/v1/daemonsets</td>")
}

func TestHtmlPrinter_ActionPrint_CoverageSectionOmittedWhenPerfect(t *testing.T) {
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "report.html")

	hp := NewHtmlPrinter(false)
	hp.SetWriter(ctx, out)

	session := cautils.NewOPASessionObjMock()
	session.ScanCoverage = cautils.ScanCoverage{
		CoverageScore:     100.0,
		EvaluatedControls: 20,
		TotalControls:     20,
		Degraded:          false,
	}

	assert.NoError(t, hp.ActionPrint(ctx, session, nil))
	assert.NoError(t, hp.CloseWriter())

	content, err := os.ReadFile(out)
	assert.NoError(t, err)
	htmlContent := string(content)

	assert.NotContains(t, htmlContent, "<h2>Scan Coverage</h2>")
}

func TestHtmlPrinter_ActionPrint_CoverageSkippedControlTable(t *testing.T) {
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "report.html")

	hp := NewHtmlPrinter(false)
	hp.SetWriter(ctx, out)

	session := cautils.NewOPASessionObjMock()
	skippedStatus := &apis.StatusInfo{
		InnerStatus: apis.StatusSkipped,
		SubStatus:   apis.SubStatusIrrelevant,
		InnerInfo:   "no matching resources in cluster",
	}
	session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{
		"C-0070": reportsummary.ControlSummary{
			ControlID:   "C-0070",
			Name:        "Host IPC",
			ScoreFactor: 6.0,
			StatusInfo:  *skippedStatus,
		},
	}
	session.ScanCoverage = cautils.ScanCoverage{
		CoverageScore:     90.0,
		EvaluatedControls: 9,
		TotalControls:     10,
		Degraded:          true,
	}

	assert.NoError(t, hp.ActionPrint(ctx, session, nil))
	assert.NoError(t, hp.CloseWriter())

	content, err := os.ReadFile(out)
	assert.NoError(t, err)
	htmlContent := string(content)

	assert.Contains(t, htmlContent, "<h2>Scan Coverage</h2>")
	assert.Contains(t, htmlContent, "<td>C-0070</td>")
	assert.Contains(t, htmlContent, "<td>Host IPC</td>")
	assert.Contains(t, htmlContent, "<td>irrelevant: no matching resources in cluster</td>")
}

// TestSortHTMLResourceTableView_DeterministicOrdering verifies that sortHTMLResourceTableView
// sorts resources deterministically across multiple levels: namespace ascending, kind ascending,
// name ascending, and ID ascending.
func TestSortHTMLResourceTableView_DeterministicOrdering(t *testing.T) {
	r1 := ResourceResult{Resource: &mockResource{namespace: "kube-system", kind: "Pod", name: "coredns", id: "id-3"}}
	r2 := ResourceResult{Resource: &mockResource{namespace: "default", kind: "Deployment", name: "api", id: "id-1"}}
	r3 := ResourceResult{Resource: &mockResource{namespace: "default", kind: "Deployment", name: "worker", id: "id-2"}}
	r4 := ResourceResult{Resource: &mockResource{namespace: "default", kind: "ConfigMap", name: "config", id: "id-0"}}
	r5 := ResourceResult{Resource: &mockResource{namespace: "", kind: "ClusterRole", name: "admin", id: "id-a"}}
	r6 := ResourceResult{Resource: &mockResource{namespace: "", kind: "ClusterRole", name: "admin", id: "id-b"}}

	input := ResourceTableView{r1, r2, r3, r4, r5, r6}
	sorted := sortHTMLResourceTableView(input)

	require.Len(t, sorted, 6)
	// Cluster-scoped (empty namespace) first, same kind and name sorted by ID
	assert.Equal(t, "id-a", sorted[0].Resource.GetID())
	assert.Equal(t, "id-b", sorted[1].Resource.GetID())
	// Namespace "default": ConfigMap before Deployment
	assert.Equal(t, "config", sorted[2].Resource.GetName())
	// Namespace "default", Deployment: "api" before "worker"
	assert.Equal(t, "api", sorted[3].Resource.GetName())
	assert.Equal(t, "worker", sorted[4].Resource.GetName())
	// Namespace "kube-system"
	assert.Equal(t, "coredns", sorted[5].Resource.GetName())

	// Reverse input order produces the identical deterministic result
	reversedInput := ResourceTableView{r6, r5, r4, r3, r2, r1}
	sortedReversed := sortHTMLResourceTableView(reversedInput)
	assert.Equal(t, sorted, sortedReversed)
}

// TestSortHTMLControlsBySeverityName_DeterministicOrdering verifies that control summaries
// are sorted primarily by severity descending, then name ascending, and finally control ID ascending.
func TestSortHTMLControlsBySeverityName_DeterministicOrdering(t *testing.T) {
	controls := map[string]reportsummary.ControlSummary{
		"C-0001": {ControlID: "C-0001", Name: "Beta High", ScoreFactor: 7.0},
		"C-0002": {ControlID: "C-0002", Name: "Alpha High", ScoreFactor: 7.0},
		"C-0003": {ControlID: "C-0003", Name: "Alpha High", ScoreFactor: 7.0},
		"C-0004": {ControlID: "C-0004", Name: "Alpha Low", ScoreFactor: 2.0},
		"C-0005": {ControlID: "C-0005", Name: "Zeta Critical", ScoreFactor: 9.0},
	}

	sorted := sortHTMLControlsBySeverityName(controls)
	require.Len(t, sorted, 5)

	// Highest severity (Critical, ScoreFactor 9.0) first
	assert.Equal(t, "C-0005", sorted[0].GetID())
	// Next severity (High, ScoreFactor 7.0): Alpha before Beta; tied name broken by ID (C-0002 before C-0003)
	assert.Equal(t, "C-0002", sorted[1].GetID())
	assert.Equal(t, "C-0003", sorted[2].GetID())
	assert.Equal(t, "C-0001", sorted[3].GetID())
	// Lowest severity (Low, ScoreFactor 2.0)
	assert.Equal(t, "C-0004", sorted[4].GetID())
}

// TestHtmlPrinter_ActionPrint_ValidHTMLTableStructure ensures that rendered HTML reports
// have balanced table tags (<tbody> matching </tbody>, <table> matching </table>, <tr> matching </tr>)
// and contain no duplicate </tr> tags or stray </div> tags.
func TestHtmlPrinter_ActionPrint_ValidHTMLTableStructure(t *testing.T) {
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "report.html")

	hp := NewHtmlPrinter(false)
	assert.NoError(t, hp.SetWriter(ctx, out))

	session := cautils.NewOPASessionObjMock()
	session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{
		"C-0001": reportsummary.ControlSummary{
			ControlID:   "C-0001",
			Name:        "Test Control 1",
			Score:       50.0,
			ScoreFactor: 8.0,
			StatusCounters: reportsummary.StatusCounters{
				FailedResources: 1,
				PassedResources: 1,
			},
		},
	}
	session.AllResources = map[string]workloadinterface.IMetadata{
		"res-1": &mockResource{kind: "Pod", name: "test-pod", namespace: "default", id: "res-1"},
	}
	session.ResourcesResult = map[string]resourcesresults.Result{
		"res-1": {
			ResourceID: "res-1",
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				{
					ControlID: "C-0001",
					Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
				},
			},
		},
	}
	session.ScanCoverage = cautils.ScanCoverage{
		CoverageScore:     80.0,
		EvaluatedControls: 8,
		TotalControls:     10,
		Degraded:          true,
	}

	imageScanData := []cautils.ImageScanData{
		{
			Image: "example.com/app:v1",
		},
	}

	assert.NoError(t, hp.ActionPrint(ctx, session, imageScanData))
	assert.NoError(t, hp.CloseWriter())

	content, err := os.ReadFile(out)
	assert.NoError(t, err)
	htmlContent := string(content)

	// Verify all table and body tags are balanced
	assert.Equal(t, strings.Count(htmlContent, "<table>")+strings.Count(htmlContent, "<table "), strings.Count(htmlContent, "</table>"),
		"table start and end tags must match")
	assert.Equal(t, strings.Count(htmlContent, "<tbody>"), strings.Count(htmlContent, "</tbody>"),
		"tbody start and end tags must match")
	assert.Equal(t, strings.Count(htmlContent, "<tr>"), strings.Count(htmlContent, "</tr>"),
		"tr start and end tags must match")

	// Ensure no duplicate </tr> (two adjacent closing tr tags)
	assert.NotContains(t, htmlContent, "</tr>\n      </tr>")
	assert.NotContains(t, htmlContent, "</tr>\r\n      </tr>")

	// Ensure no stray </div> in failed resources section
	assert.NotContains(t, htmlContent, "</div>")
}
