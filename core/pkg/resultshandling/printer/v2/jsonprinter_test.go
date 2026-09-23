package printer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/anchore/grype/grype/match"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/prioritization"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewJsonPrinter(t *testing.T) {
	pp := NewJsonPrinter()
	assert.NotNil(t, pp)
}

// TestSetWriter_Json_CaseInsensitiveExtension guards against the extension
// check regressing to a case-sensitive comparison: an outputFile whose
// extension already matches --output's target extension in a different case
// (e.g. "Report.JSON") must not have the extension appended a second time.
func TestSetWriter_Json_CaseInsensitiveExtension(t *testing.T) {
	tests := []struct {
		name       string
		outputFile string
	}{
		{"lowercase extension", "report.json"},
		{"uppercase extension", "Report.JSON"},
		{"mixed case extension", "Report.Json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			target := tmpDir + string(os.PathSeparator) + tt.outputFile

			jp := NewJsonPrinter()
			require.NoError(t, jp.SetWriter(context.TODO(), target))
			require.NotNil(t, jp.writer)
			defer jp.writer.Close()

			assert.Equal(t, target, jp.writer.Name(), "extension should not be appended a second time")
		})
	}
}

// TestSetWriter_Json_StdoutAndDevNullSinks guards the well-known output
// sinks: /dev/stdout must write to real stdout (not a /dev/stdout.json
// file) and /dev/null must discard, exactly like PrettyPrinter treats
// them, for every printer that routes through ResolveOutputFile.
func TestSetWriter_Json_StdoutAndDevNullSinks(t *testing.T) {
	jp := NewJsonPrinter()
	require.NoError(t, jp.SetWriter(context.TODO(), os.Stdout.Name()))
	require.NotNil(t, jp.writer)
	assert.Equal(t, os.Stdout.Name(), jp.writer.Name(), "stdout sink must resolve to real stdout")
	require.NoError(t, jp.CloseWriter())

	jp = NewJsonPrinter()
	require.NoError(t, jp.SetWriter(context.TODO(), os.DevNull))
	require.NotNil(t, jp.writer)
	assert.Equal(t, os.DevNull, jp.writer.Name(), "devnull sink must resolve to /dev/null, not /dev/null.json")
	require.NoError(t, jp.CloseWriter())
}

func TestScore_Json(t *testing.T) {
	tests := []struct {
		name  string
		score float32
		want  string
	}{
		{
			name:  "Score not an integer",
			score: 20.7,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 21\n",
		},
		{
			name:  "Fractional score below perfect",
			score: 99.5,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 99\n",
		},
		{
			name:  "Score less than 0",
			score: -20.0,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 0\n",
		},
		{
			name:  "Score greater than 100",
			score: 120.0,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 100\n",
		},
		{
			name:  "Score 50",
			score: 50.0,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 50\n",
		},
		{
			name:  "Zero Score",
			score: 0.0,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 0\n",
		},
		{
			name:  "Perfect Score",
			score: 100,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 100\n",
		},
	}

	jp := NewJsonPrinter()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary file to capture output
			f, err := os.CreateTemp("", "pdfPrinter-score-output")
			if err != nil {
				panic(err)
			}
			defer f.Close()

			// Redirect stderr to the temporary file
			oldStderr := os.Stderr
			defer func() {
				os.Stderr = oldStderr
			}()
			os.Stderr = f

			// Print the score using the `Score` function
			jp.Score(tt.score)

			// Read the contents of the temporary file
			f.Seek(0, 0)
			got, err := io.ReadAll(f)
			if err != nil {
				panic(err)
			}
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestActionPrintIncludesExceptionAuditWhenSet(t *testing.T) {
	session := cautils.NewOPASessionObjMock()
	session.ExceptionAudit = &cautils.ExceptionAudit{
		Generated: true,
		Summary: cautils.ExceptionAuditSummary{
			Total:   1,
			Active:  1,
			Matched: 1,
		},
		Items: []cautils.ExceptionAuditItem{
			{
				Name:       "matched-exception",
				Status:     "matched",
				MatchCount: 1,
				ControlIDs: []string{"C-0001"},
			},
		},
	}

	got := jsonPrinterOutput(t, session)

	exceptionAudit, ok := got["exceptionAudit"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, true, exceptionAudit["generated"])

	summary, ok := exceptionAudit["summary"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(1), summary["total"])
	assert.Equal(t, float64(1), summary["active"])
	assert.Equal(t, float64(1), summary["matched"])

	items, ok := exceptionAudit["items"].([]any)
	require.True(t, ok)
	require.Len(t, items, 1)
	item, ok := items[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "matched-exception", item["name"])
}

func TestActionPrintOmitsExceptionAuditWhenNil(t *testing.T) {
	got := jsonPrinterOutput(t, cautils.NewOPASessionObjMock())

	_, ok := got["exceptionAudit"]
	assert.False(t, ok)
}

func TestActionPrintIncludesSessionIDAsReportGUID(t *testing.T) {
	session := cautils.NewOPASessionObjMock()
	session.SessionID = "scan-6f012842"

	got := jsonPrinterOutput(t, session)

	assert.Equal(t, "scan-6f012842", got["reportGUID"])
}

func jsonPrinterOutput(t *testing.T, session *cautils.OPASessionObj) map[string]any {
	t.Helper()

	tmpJson, err := os.CreateTemp("", "json-exception-audit-*.json")
	require.NoError(t, err)
	defer func() {
		_ = os.Remove(tmpJson.Name())
	}()

	jp := NewJsonPrinter()
	jp.writer = tmpJson
	require.NoError(t, jp.ActionPrint(context.Background(), session, nil))
	require.NoError(t, tmpJson.Close())

	rawJson, err := os.ReadFile(tmpJson.Name())
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(rawJson, &got))
	return got
}

func TestConvertToCVESummary(t *testing.T) {
	cves := []imageprinter.CVE{
		{
			Severity:    "High",
			ID:          "CVE-2021-1234",
			Package:     "example-package",
			Version:     "1.0.0",
			FixVersions: []string{"1.0.1", "1.0.2"},
			FixedState:  "true",
		},
		{
			Severity:    "Medium",
			ID:          "CVE-2021-5678",
			Package:     "another-package",
			Version:     "2.0.0",
			FixVersions: []string{"2.0.1"},
			FixedState:  "false",
		},
	}

	want := []reportsummary.CVESummary{
		{
			Severity:    "High",
			ID:          "CVE-2021-1234",
			Package:     "example-package",
			Version:     "1.0.0",
			FixVersions: []string{"1.0.1", "1.0.2"},
			FixedState:  "true",
		},
		{
			Severity:    "Medium",
			ID:          "CVE-2021-5678",
			Package:     "another-package",
			Version:     "2.0.0",
			FixVersions: []string{"2.0.1"},
			FixedState:  "false",
		},
	}

	got := convertToCVESummary(cves)

	assert.Equal(t, want, got)
}

func TestConvertToPackageScores(t *testing.T) {
	packageScores := map[string]*imageprinter.PackageScore{
		"example-package": {
			Name:                    "example-package",
			Version:                 "1.0.0",
			Score:                   80.0,
			MapSeverityToCVEsNumber: map[string]int{"High": 2, "Medium": 1},
		},
		"another-package": {
			Name:                    "another-package",
			Version:                 "2.0.0",
			Score:                   60.0,
			MapSeverityToCVEsNumber: map[string]int{"High": 1, "Medium": 0},
		},
	}

	want := map[string]*reportsummary.PackageSummary{
		"example-package": {
			Name:                    "example-package",
			Version:                 "1.0.0",
			Score:                   80.0,
			MapSeverityToCVEsNumber: map[string]int{"High": 2, "Medium": 1},
		},
		"another-package": {
			Name:                    "another-package",
			Version:                 "2.0.0",
			Score:                   60.0,
			MapSeverityToCVEsNumber: map[string]int{"High": 1, "Medium": 0},
		},
	}

	got := convertToPackageScores(packageScores)

	assert.Equal(t, want, got)
}

func TestConvertToReportSummary(t *testing.T) {
	input := map[string]*imageprinter.SeveritySummary{
		"High": {
			NumberOfCVEs:        10,
			NumberOfFixableCVEs: 5,
		},
		"Medium": {
			NumberOfCVEs:        5,
			NumberOfFixableCVEs: 2,
		},
	}

	want := map[string]*reportsummary.SeveritySummary{
		"High": {
			NumberOfCVEs:        10,
			NumberOfFixableCVEs: 5,
		},
		"Medium": {
			NumberOfCVEs:        5,
			NumberOfFixableCVEs: 2,
		},
	}

	got := convertToReportSummary(input)

	assert.Equal(t, want, got)
}

func TestEnrichControlsWithSeverity(t *testing.T) {
	tests := []struct {
		name         string
		scoreFactor  float32
		wantSeverity string
	}{
		{
			name:         "Critical severity",
			scoreFactor:  9.0,
			wantSeverity: "Critical",
		},
		{
			name:         "High severity",
			scoreFactor:  8.0,
			wantSeverity: "High",
		},
		{
			name:         "Medium severity",
			scoreFactor:  6.0,
			wantSeverity: "Medium",
		},
		{
			name:         "Low severity",
			scoreFactor:  3.0,
			wantSeverity: "Low",
		},
		{
			name:         "Unknown severity",
			scoreFactor:  0.0,
			wantSeverity: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controls := reportsummary.ControlSummaries{
				"C-0001": reportsummary.ControlSummary{
					ControlID:   "C-0001",
					Name:        "Test Control",
					ScoreFactor: tt.scoreFactor,
				},
			}

			enrichedControls := enrichControlsWithSeverity(controls)

			assert.Equal(t, 1, len(enrichedControls))
			assert.Equal(t, tt.wantSeverity, enrichedControls["C-0001"].Severity)
			assert.Equal(t, "Test Control", enrichedControls["C-0001"].Name)
			assert.Equal(t, tt.scoreFactor, enrichedControls["C-0001"].ScoreFactor)
		})
	}
}

func TestConvertToPostureReportWithSeverity(t *testing.T) {
	// Create a mock PostureReport with controls having different severity levels
	mockReport := reportsummary.MockSummaryDetails()

	// Get the controls from mock data
	controls := mockReport.Controls

	// Create a minimal PostureReport
	report := &reporthandlingv2.PostureReport{
		SummaryDetails: *mockReport,
	}

	// Convert to PostureReportWithSeverity
	reportWithSeverity := ConvertToPostureReportWithSeverity(report)

	// Verify controls have severity field
	assert.NotNil(t, reportWithSeverity)
	assert.NotNil(t, reportWithSeverity.SummaryDetails.Controls)

	// Verify each control in the original report has a corresponding enriched control with severity
	for controlID, control := range controls {
		enrichedControl, exists := reportWithSeverity.SummaryDetails.Controls[controlID]
		assert.True(t, exists, "Control %s should exist in enriched controls", controlID)
		assert.NotEmpty(t, enrichedControl.Severity, "Severity should not be empty for control %s", controlID)
		assert.Equal(t, control.ControlID, enrichedControl.ControlID, "Control ID should match")
		assert.Equal(t, control.ScoreFactor, enrichedControl.ScoreFactor, "ScoreFactor should match")
	}
}

func TestConvertToPostureReportWithSeverityNilCheck(t *testing.T) {
	// Test that nil report returns nil
	result := ConvertToPostureReportWithSeverity(nil)
	assert.Nil(t, result, "Converting nil report should return nil")
}

func TestEnrichResultsWithSeverity(t *testing.T) {
	// Create mock control summaries
	controlSummaries := reportsummary.ControlSummaries{
		"C-0001": reportsummary.ControlSummary{
			ControlID:   "C-0001",
			Name:        "Test Control High",
			ScoreFactor: 8.0,
		},
		"C-0002": reportsummary.ControlSummary{
			ControlID:   "C-0002",
			Name:        "Test Control Medium",
			ScoreFactor: 6.0,
		},
	}

	// Create mock results with associated controls
	results := []resourcesresults.Result{
		{
			ResourceID: "test-resource-1",
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				{
					ControlID: "C-0001",
					Name:      "Test Control High",
				},
			},
		},
		{
			ResourceID: "test-resource-2",
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				{
					ControlID: "C-0002",
					Name:      "Test Control Medium",
				},
				{
					ControlID: "C-0003", // Not in control summaries
					Name:      "Unknown Control",
				},
			},
		},
	}

	// Enrich results with severity
	enrichedResults := enrichResultsWithSeverity(results, controlSummaries, nil)

	// Verify results structure
	assert.Equal(t, 2, len(enrichedResults))

	// Verify first result
	assert.Equal(t, "test-resource-1", enrichedResults[0].ResourceID)
	assert.Equal(t, 1, len(enrichedResults[0].AssociatedControls))
	assert.Equal(t, "High", enrichedResults[0].AssociatedControls[0].Severity)
	assert.Equal(t, "C-0001", enrichedResults[0].AssociatedControls[0].ControlID)

	// Verify second result
	assert.Equal(t, "test-resource-2", enrichedResults[1].ResourceID)
	assert.Equal(t, 2, len(enrichedResults[1].AssociatedControls))
	assert.Equal(t, "Medium", enrichedResults[1].AssociatedControls[0].Severity)
	assert.Equal(t, "C-0002", enrichedResults[1].AssociatedControls[0].ControlID)
	// Verify unknown control gets "Unknown" severity
	assert.Equal(t, "Unknown", enrichedResults[1].AssociatedControls[1].Severity)
	assert.Equal(t, "C-0003", enrichedResults[1].AssociatedControls[1].ControlID)
}

func TestEnrichResultsWithSeverity_PopulatesEvidenceFromResources(t *testing.T) {
	controlSummaries := reportsummary.ControlSummaries{
		"C-0001": reportsummary.ControlSummary{ControlID: "C-0001", ScoreFactor: 8.0},
	}
	results := []resourcesresults.Result{
		{
			ResourceID: "test-resource-1",
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				{
					ControlID: "C-0001",
					ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
						{
							Paths: []armotypes.PosturePaths{
								{FailedPath: "spec.hostPID"},
								{FailedPath: "spec.doesNotExist"},
								{FailedPath: "data.password"},
							},
						},
					},
				},
			},
		},
	}
	allResources := map[string]workloadinterface.IMetadata{
		"test-resource-1": &mockResource{
			kind: "Secret",
			obj: map[string]any{
				"spec": map[string]any{"hostPID": true},
				"data": map[string]any{"password": "hunter2"},
			},
		},
		// unrelated entry to confirm lookup is keyed correctly
		"test-resource-2": &mockResource{obj: map[string]any{}},
	}

	enrichedResults := enrichResultsWithSeverity(results, controlSummaries, allResources)

	require.Len(t, enrichedResults, 1)
	evidence := enrichedResults[0].AssociatedControls[0].Evidence
	// spec.doesNotExist is unresolvable (omitted) and data.password is
	// redacted (Secret kind) - only spec.hostPID should surface.
	require.Len(t, evidence, 1)
	assert.Equal(t, PathValue{Path: "spec.hostPID", Value: "true"}, evidence[0])

	// The original FailedPath strings on the embedded control are untouched.
	rawPaths := enrichedResults[0].AssociatedControls[0].ResourceAssociatedRules[0].Paths
	require.Len(t, rawPaths, 3)
	assert.Equal(t, "spec.hostPID", rawPaths[0].FailedPath)
}

func TestEnrichResultsWithSeverity_NoResourceMatchLeavesEvidenceNil(t *testing.T) {
	controlSummaries := reportsummary.ControlSummaries{}
	results := []resourcesresults.Result{
		{
			ResourceID: "missing-resource",
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				{
					ControlID: "C-0001",
					ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
						{Paths: []armotypes.PosturePaths{{FailedPath: "spec.hostPID"}}},
					},
				},
			},
		},
	}

	enrichedResults := enrichResultsWithSeverity(results, controlSummaries, nil)

	require.Len(t, enrichedResults, 1)
	assert.Nil(t, enrichedResults[0].AssociatedControls[0].Evidence)
}

// The reference uses the established report conversion on an independent
// fixture: FinalizeResults mutates defaults and shared control slice order.
func TestConfigurationJSONStreamingMatchesConversion(t *testing.T) {
	for _, tc := range []struct {
		name      string
		size      int
		configure func(*cautils.OPASessionObj)
	}{
		{name: "empty"},
		{name: "single", size: 1},
		{name: "multiple", size: 3},
		{name: "omit raw", size: 3, configure: func(s *cautils.OPASessionObj) { s.OmitRawResources = true }},
		{name: "missing raw", size: 3, configure: func(s *cautils.OPASessionObj) { delete(s.AllResources, "resource-000001") }},
		{name: "all raw missing", size: 1, configure: func(s *cautils.OPASessionObj) { clear(s.AllResources) }},
		{name: "labels without results", size: 3, configure: func(s *cautils.OPASessionObj) {
			s.LabelsToCopy = []string{"app", "absent"}
			delete(s.ResourcesResult, "resource-000001")
		}},
		{name: "no matching labels", size: 1, configure: func(s *cautils.OPASessionObj) { s.LabelsToCopy = []string{"absent"} }},
		{name: "key differs from resource ID", size: 2, configure: func(s *cautils.OPASessionObj) {
			r := s.ResourcesResult["resource-000000"]
			delete(s.ResourcesResult, "resource-000000")
			r.PrioritizedResource = &prioritization.PrioritizedResource{Score: 1}
			s.ResourcesResult["different-key"] = r
			s.ResourcesPrioritized["different-key"] = prioritization.PrioritizedResource{Score: 42, ResourceID: r.ResourceID}
		}},
		{name: "unsorted and unknown controls", size: 2, configure: func(s *cautils.OPASessionObj) {
			delete(s.Report.SummaryDetails.Controls, "C-0000")
			for _, r := range s.ResourcesResult {
				slices.Reverse(r.AssociatedControls)
			}
		}},
		{name: "optional sections", size: 1, configure: func(s *cautils.OPASessionObj) {
			s.ExceptionAudit = &cautils.ExceptionAudit{Generated: true, Items: []cautils.ExceptionAuditItem{{Name: "exception", MatchCount: 1, MatchedResources: []cautils.ExceptionAuditMatch{{ResourceID: "resource-000000", ControlID: "C-0000"}}}}}
			s.NamespaceSummaries = cautils.NamespaceSummaries{{Namespace: "default", ResourceCount: 1}}
			s.ScanCoverage.VacuousFrameworks = []string{"example"}
			s.Report.Attributes = []reportsummary.PostureAttributes{{Attribute: "example", Values: []string{"value"}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			legacy, session := configurationOutputFixture(t, tc.size), configurationOutputFixture(t, tc.size)
			for id, source := range legacy.ResourceSource {
				session.ResourceSource[id] = source
			}
			if tc.configure != nil {
				tc.configure(legacy)
				tc.configure(session)
			}
			before := snapshotJSONSession(t, session)
			expected := ConvertToPostureReportWithSeverityLabelsAndCoverage(FinalizeResults(legacy), legacy.LabelsToCopy, legacy.AllResources, &legacy.ScanCoverage)
			expected.ExceptionAudit = legacy.ExceptionAudit
			expected.NamespaceSummaries = legacy.NamespaceSummaries
			want, err := json.Marshal(expected)
			require.NoError(t, err)
			var output bytes.Buffer
			require.NoError(t, writeConfigurationJSON(&output, session, nil))
			require.NoError(t, checkJSONDocument(output.Bytes()))
			require.JSONEq(t, string(want), output.String())
			require.Equal(t, before, snapshotJSONSession(t, session))
			var again bytes.Buffer
			require.NoError(t, writeConfigurationJSON(&again, session, nil))
			require.Equal(t, output.String(), again.String())
		})
	}
}

func snapshotJSONSession(t *testing.T, s *cautils.OPASessionObj) string {
	t.Helper()
	// Capture raw objects as well as result/control ordering. Marshaling the
	// whole session would omit the objects behind its metadata interfaces.
	objects := map[string]any{}
	for id, r := range s.AllResources {
		objects[id] = r.GetObject()
	}
	b, err := json.Marshal([]any{s.Report, s.Metadata, s.ResourcesResult, s.ResourcesPrioritized, s.ResourceSource, objects, s.ScanCoverage, s.ExceptionAudit, s.NamespaceSummaries})
	require.NoError(t, err)
	return string(b)
}

func TestConfigurationJSONDefaultsStayLocal(t *testing.T) {
	s := cautils.NewOPASessionObjMock()
	s.SessionID = "session-id"
	s.Metadata = nil
	before := snapshotJSONSession(t, s)
	var output bytes.Buffer
	start := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, writeConfigurationJSON(&output, s, nil))
	var doc PostureReportWithSeverity
	require.NoError(t, json.Unmarshal(output.Bytes(), &doc))
	generated, err := time.Parse(time.RFC3339, doc.ReportGenerationTime)
	require.NoError(t, err)
	require.False(t, generated.Before(start))
	require.Equal(t, s.SessionID, doc.ReportID)
	require.Equal(t, cautils.AdoptClusterName(scanContextName(s)), doc.ClusterName)
	require.Equal(t, reporthandlingv2.Metadata{}, doc.Metadata)
	require.Equal(t, before, snapshotJSONSession(t, s))
}

func TestConfigurationJSONImageSummaryStaysLocal(t *testing.T) {
	s := configurationOutputFixture(t, 1)
	before := snapshotJSONSession(t, s)
	image := buildSeverityExceptionImageScanData()
	matches := image.Matches.Sorted()
	for i := range matches {
		matches[i].Vulnerability.Metadata = image.VulnerabilityProvider.(severityRegressionVulnerabilityProvider).metadataByID[matches[i].Vulnerability.ID]
	}
	image.Matches = match.NewMatches(matches...)
	var output bytes.Buffer
	require.NoError(t, writeConfigurationJSON(&output, s, []cautils.ImageScanData{image}))
	var doc PostureReportWithSeverity
	require.NoError(t, json.Unmarshal(output.Bytes(), &doc))
	summary := buildMachineImageScanSummary([]cautils.ImageScanData{image})
	require.Equal(t, convertToCVESummary(summary.CVEs), doc.SummaryDetails.Vulnerabilities.CVESummary)
	require.Equal(t, convertToPackageScores(summary.PackageScores), map[string]*reportsummary.PackageSummary(doc.SummaryDetails.Vulnerabilities.PackageScores))
	require.Equal(t, summary.Images, doc.SummaryDetails.Vulnerabilities.Images)
	require.Equal(t, before, snapshotJSONSession(t, s))
}

// checkJSONDocument rejects duplicate keys, including nested ones, and any
// second document. json.Unmarshal alone accepts duplicate object properties.
func checkJSONDocument(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, container := token.(json.Delim)
		if !container {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok {
					return fmt.Errorf("non-string object key")
				}
				if seen[name] {
					return fmt.Errorf("duplicate key %q", name)
				}
				seen[name] = true
				if err := walk(); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := walk(); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("unexpected delimiter %q", delim)
		}
		_, err = d.Token()
		return err
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("expected EOF, got %v", err)
	}
	return nil
}

func TestCheckJSONDocument(t *testing.T) {
	for _, bad := range []string{`{"runs":[{"results":[],"results":[]}]}`, `{"a":{"x":1,"x":2}}`, `{} {}`, `{"a":[`} {
		require.Error(t, checkJSONDocument([]byte(bad)))
	}
	require.NoError(t, checkJSONDocument([]byte(`{"a":[{"x":1},{"x":2}]}`)))
}

var errOutputTest = errors.New("output failed")

type failAfterWriter struct {
	remaining         int
	failed            bool
	callsAfterFailure int
}

func (w *failAfterWriter) Write(p []byte) (int, error) {
	if w.failed {
		w.callsAfterFailure++
		return 0, errOutputTest
	}
	if len(p) > w.remaining {
		n := w.remaining
		w.failed = true
		return n, errOutputTest
	}
	w.remaining -= len(p)
	return len(p), nil
}

type shortOutputWriter struct{}

func (shortOutputWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestConfigurationJSONWriteFailures(t *testing.T) {
	s := configurationOutputFixture(t, 2)
	s.LabelsToCopy = []string{"app"}
	before := snapshotJSONSession(t, s)
	var output bytes.Buffer
	require.NoError(t, writeConfigurationJSON(&output, s, nil))
	cuts := []int{0, 1, output.Len() - 1}
	for _, marker := range []string{`"summaryDetails":`, `"results":[`, `"resourceID":"resource-000001"`, `"resources":[`, `"resourceLabels":{`} {
		index := strings.Index(output.String(), marker)
		require.NotEqual(t, -1, index, marker)
		cuts = append(cuts, index, index+len(marker)+1)
	}
	for _, cut := range cuts {
		w := &failAfterWriter{remaining: cut}
		require.ErrorIs(t, writeConfigurationJSON(w, s, nil), errOutputTest, "cut %d", cut)
		require.Zero(t, w.callsAfterFailure)
		require.Equal(t, before, snapshotJSONSession(t, s))
	}
	require.ErrorIs(t, writeConfigurationJSON(shortOutputWriter{}, s, nil), io.ErrShortWrite)
}

func TestConfigurationJSONEncodingFailures(t *testing.T) {
	for _, stage := range []string{"header", "result", "raw resource"} {
		t.Run(stage, func(t *testing.T) {
			s := configurationOutputFixture(t, 2)
			switch stage {
			case "header":
				s.Report.SummaryDetails.Score = float32(math.NaN())
			case "result":
				s.ResourcesPrioritized["resource-000000"] = prioritization.PrioritizedResource{Score: math.NaN()}
			case "raw resource":
				s.AllResources["resource-000000"].GetObject()["unsupported"] = make(chan int)
			}
			var output bytes.Buffer
			err := writeConfigurationJSON(&output, s, nil)
			require.Error(t, err)
			require.Error(t, checkJSONDocument(output.Bytes()))
		})
	}
}

type observedResource struct {
	workloadinterface.IMetadata
	observe func()
}

func (r observedResource) GetObject() map[string]interface{} {
	r.observe()
	return r.IMetadata.GetObject()
}

type stopAtResultWriter struct {
	bytes.Buffer
	marker string
}

func (w *stopAtResultWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte(w.marker)) {
		return 0, errOutputTest
	}
	return w.Buffer.Write(p)
}

func TestConfigurationJSONStopsBeforeTransformingLaterResources(t *testing.T) {
	s := configurationOutputFixture(t, 2)
	w := &stopAtResultWriter{marker: `"resourceID":"resource-000000"`}
	reads := [2]int{}
	for i := range reads {
		id := fmt.Sprintf("resource-%06d", i)
		s.AllResources[id] = observedResource{s.AllResources[id], func() {
			require.Contains(t, w.String(), `"results":[`)
			reads[i]++
		}}
	}
	require.ErrorIs(t, writeConfigurationJSON(w, s, nil), errOutputTest)
	require.Positive(t, reads[0])
	require.Zero(t, reads[1])
}

func TestConfigurationJSONCoverageMatchesConversion(t *testing.T) {
	for _, coverage := range []string{
		`{}`, `{"failedGVRPulls":[{}]}`, `{"notEvaluatedControls":[{}]}`,
		`{"partialGVRPulls":[{}]}`, `{"policyDegradations":[{}]}`,
		`{"skippedManifests":[{}]}`, `{"vacuousFrameworks":["example"]}`,
	} {
		t.Run(coverage, func(t *testing.T) {
			legacy, session := configurationOutputFixture(t, 0), configurationOutputFixture(t, 0)
			require.NoError(t, json.Unmarshal([]byte(coverage), &legacy.ScanCoverage))
			require.NoError(t, json.Unmarshal([]byte(coverage), &session.ScanCoverage))
			expected := ConvertToPostureReportWithSeverityLabelsAndCoverage(FinalizeResults(legacy), nil, nil, &legacy.ScanCoverage)
			want, err := json.Marshal(expected)
			require.NoError(t, err)
			var output bytes.Buffer
			require.NoError(t, writeConfigurationJSON(&output, session, nil))
			require.JSONEq(t, string(want), output.String())
		})
	}
}
