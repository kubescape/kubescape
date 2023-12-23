package printer

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/stretchr/testify/assert"
)

func TestJunitPrinter(t *testing.T) {
	// Verbose mode off
	jp := NewJunitPrinter(false)
	assert.NotNil(t, jp)
	assert.Equal(t, false, jp.verbose)

	// Verbose mode on
	jp = NewJunitPrinter(true)
	assert.NotNil(t, jp)
	assert.Equal(t, true, jp.verbose)
}

func TestScore_Junit(t *testing.T) {
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

	jp := NewJunitPrinter(false)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary file to capture output
			f, err := os.CreateTemp("", "score-output")
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

func TestTestSuites(t *testing.T) {
	results := cautils.NewOPASessionObjMock()
	junitTestSuites := testsSuites(results)

	assert.NotNil(t, junitTestSuites)
	assert.Equal(t, listTestsSuite(results), junitTestSuites.Suites)
	assert.Equal(t, results.Report.SummaryDetails.NumberOfControls().All(), junitTestSuites.Tests)
	assert.Equal(t, "Kubescape Scanning", junitTestSuites.Name)
}

func TestListTestSuites(t *testing.T) {
	// Non empty OPASessionObj
	results := cautils.NewOPASessionObjMock()
	testsSuites := listTestsSuite(results)

	expectedTestSuites := []JUnitTestSuite{
		{
			XMLName:   xml.Name{Space: "", Local: ""},
			Tests:     0,
			Name:      "kubescape",
			Errors:    0,
			Failures:  0,
			Hostname:  "",
			ID:        0,
			Skipped:   "",
			Time:      "",
			Timestamp: "0001-01-01 00:00:00 +0000 UTC",
			Properties: []JUnitProperty{
				{Name: "complianceScore", Value: "0.00"},
			},
			TestCases: []JUnitTestCase(nil),
		},
	}

	assert.Equal(t, expectedTestSuites, testsSuites)
}

func TestProperties(t *testing.T) {
	tests := []struct {
		name             string
		score            float32
		expectedProperty []JUnitProperty
	}{
		{
			name:  "Score not an integer",
			score: 20.7,
			expectedProperty: []JUnitProperty{
				{
					Name:  "complianceScore",
					Value: fmt.Sprintf("%.2f", 20.7),
				},
			},
		},
		{
			name:  "Score less than 0",
			score: -20.0,
			expectedProperty: []JUnitProperty{
				{
					Name:  "complianceScore",
					Value: fmt.Sprintf("%.2f", -20.0),
				},
			},
		},
		{
			name:  "Score greater than 100",
			score: 120.0,
			expectedProperty: []JUnitProperty{
				{
					Name:  "complianceScore",
					Value: fmt.Sprintf("%.2f", 120.0),
				},
			},
		},
		{
			name:  "Score 50",
			score: 50.0,
			expectedProperty: []JUnitProperty{
				{
					Name:  "complianceScore",
					Value: fmt.Sprintf("%.2f", 50.0),
				},
			},
		},
		{
			name:  "Zero Score",
			score: 0.0,
			expectedProperty: []JUnitProperty{
				{
					Name:  "complianceScore",
					Value: fmt.Sprintf("%.2f", 0.0),
				},
			},
		},
		{
			name:  "Perfect Score",
			score: 100,
			expectedProperty: []JUnitProperty{
				{
					Name:  "complianceScore",
					Value: fmt.Sprintf("%.2f", 100.0),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedProperty, properties(tt.score))
		})
	}
}

func TestSetWriter_Junit(t *testing.T) {
	tests := []struct {
		name       string
		outputFile string
		expected   string
	}{
		{
			name:       "Output file name contains doesn't contain any extension",
			outputFile: "customFilename",
			expected:   "customFilename.xml",
		},
		{
			name:       "Output file name contains .xml",
			outputFile: "customFilename.xml",
			expected:   "customFilename.xml",
		},
		{
			name:       "Output file name is empty",
			outputFile: "",
			expected:   "/dev/stdout",
		},
	}

	jp := NewJunitPrinter(false)
	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			jp.SetWriter(ctx, tt.outputFile)
			assert.Equal(t, tt.expected, jp.writer.Name())
		})
	}
}
