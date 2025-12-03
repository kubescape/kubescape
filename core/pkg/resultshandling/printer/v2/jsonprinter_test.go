package printer

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
)

func TestNewJsonPrinter(t *testing.T) {
	pp := NewJsonPrinter()
	assert.NotNil(t, pp)
	assert.Empty(t, pp)
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
			got, err := ioutil.ReadAll(f)
			if err != nil {
				panic(err)
			}
			assert.Equal(t, tt.want, string(got))
		})
	}
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
		"High": &imageprinter.SeveritySummary{
			NumberOfCVEs:        10,
			NumberOfFixableCVEs: 5,
		},
		"Medium": &imageprinter.SeveritySummary{
			NumberOfCVEs:        5,
			NumberOfFixableCVEs: 2,
		},
	}

	want := map[string]*reportsummary.SeveritySummary{
		"High": &reportsummary.SeveritySummary{
			NumberOfCVEs:        10,
			NumberOfFixableCVEs: 5,
		},
		"Medium": &reportsummary.SeveritySummary{
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
	enrichedResults := enrichResultsWithSeverity(results, controlSummaries)

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
