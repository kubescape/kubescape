package printer

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
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
