package configurationprinter

import (
	"io"
	"os"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/stretchr/testify/assert"
)

type MockISeverityCounters struct {
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
}

func (m *MockISeverityCounters) NumberOfCriticalSeverity() int {
	return m.CriticalCount
}

func (m *MockISeverityCounters) NumberOfHighSeverity() int {
	return m.HighCount
}

func (m *MockISeverityCounters) NumberOfMediumSeverity() int {
	return m.MediumCount
}

func (m *MockISeverityCounters) NumberOfLowSeverity() int {
	return m.LowCount
}

func (m *MockISeverityCounters) Increase(severity string, amount int) {
}

func TestNewFrameworkPrinter(t *testing.T) {
	// Test case 1: Verifying default verbose mode
	frameworkPrinter := NewFrameworkPrinter(false)
	assert.NotNil(t, frameworkPrinter)
	assert.Equal(t, false, frameworkPrinter.verboseMode)

	// Test case 2: Setting verbose mode to true
	frameworkPrinter = NewFrameworkPrinter(true)
	assert.NotNil(t, frameworkPrinter)
	assert.Equal(t, true, frameworkPrinter.verboseMode)
}

func TestGetVerboseMode(t *testing.T) {
	// Test case 1: Verifying false verbose mode
	frameworkPrinter := NewFrameworkPrinter(false)
	assert.Equal(t, false, frameworkPrinter.getVerboseMode())

	// Test case 2: Setting verbose mode to true
	frameworkPrinter = NewFrameworkPrinter(true)
	assert.Equal(t, true, frameworkPrinter.getVerboseMode())
}

func TestShortRowFormat(t *testing.T) {
	tests := []struct {
		name         string
		rows         [][]string
		expectedRows [][]string
	}{
		{
			name:         "Test Empty rows",
			rows:         [][]string{},
			expectedRows: [][]string{},
		},
		{
			name: "Test Non empty row",
			rows: [][]string{
				{"Medium", "Control 1", "2", "20", "0.8"},
			},
			expectedRows: [][]string{[]string{"Severity           : Medium\nControl Name       : Control 1\nFailed Resources   : 2\nAll Resources      : 20\n% Compliance-Score : 0.8"}},
		},
		{
			name: "Test Non empty rows",
			rows: [][]string{
				{"Medium", "Control 1", "2", "20", "0.8"},
				{"Low", "Control 2", "0", "30", "1.0"},
			},
			expectedRows: [][]string{[]string{"Severity           : Medium\nControl Name       : Control 1\nFailed Resources   : 2\nAll Resources      : 20\n% Compliance-Score : 0.8"}, []string{"Severity           : Low\nControl Name       : Control 2\nFailed Resources   : 0\nAll Resources      : 30\n% Compliance-Score : 1.0"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedRows, shortFormatRow(tt.rows))
		})
	}
}

func TestRenderSeverityCountersSummary(t *testing.T) {
	tests := []struct {
		name     string
		counters MockISeverityCounters
		expected [][]string
	}{
		{
			name:     "All empty",
			counters: MockISeverityCounters{},
			expected: [][]string{[]string{"Critical", "0"}, []string{"High", "0"}, []string{"Medium", "0"}, []string{"Low", "0"}},
		},
		{
			name: "All different",
			counters: MockISeverityCounters{
				CriticalCount: 7,
				HighCount:     17,
				MediumCount:   27,
				LowCount:      37,
			},
			expected: [][]string{[]string{"Critical", "7"}, []string{"High", "17"}, []string{"Medium", "27"}, []string{"Low", "37"}},
		},
		{
			name: "All equal",
			counters: MockISeverityCounters{
				CriticalCount: 7,
				HighCount:     7,
				MediumCount:   7,
				LowCount:      7,
			},
			expected: [][]string{[]string{"Critical", "7"}, []string{"High", "7"}, []string{"Medium", "7"}, []string{"Low", "7"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, renderSeverityCountersSummary(&tt.counters))
		})
	}
}

func TestPrintSummaryTable(t *testing.T) {
	tests := []struct {
		name             string
		summaryDetails   *reportsummary.SummaryDetails
		sortedControlIDs [][]string
		want             string
	}{
		{
			name: "All empty",
			summaryDetails: &reportsummary.SummaryDetails{
				Frameworks: []reportsummary.FrameworkSummary{
					{
						Name: "CIS Kubernetes Benchmark",
					},
					{
						Name: "nsa",
					},
					{
						Name: "mitre",
					},
				},
			},
			sortedControlIDs: [][]string{},
			want:             "\nKubescape did not scan any resources. Make sure you are scanning valid manifests (Deployments, Pods, etc.)\n",
		},
	}

	fp := NewFrameworkPrinter(false)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary file to capture output
			f, err := os.CreateTemp("", "print")
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

			fp.PrintSummaryTable(f, tt.summaryDetails, tt.sortedControlIDs)

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
