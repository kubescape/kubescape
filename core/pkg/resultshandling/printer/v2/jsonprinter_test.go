package printer

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
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
