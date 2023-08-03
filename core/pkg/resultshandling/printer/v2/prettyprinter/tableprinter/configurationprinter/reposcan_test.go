package configurationprinter

import (
	"testing"

	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

func TestRepoScan_GenerateCountingCategoryRow(t *testing.T) {
	tests := []struct {
		name           string
		controlSummary reportsummary.ControlSummary
		expectedRow    []string
		inputPatterns  []string
	}{
		{
			name: "multiple files",
			controlSummary: reportsummary.ControlSummary{
				ControlID: "ctrl1",
				Name:      "ctrl1",
				StatusCounters: reportsummary.StatusCounters{
					FailedResources:  5,
					PassedResources:  3,
					SkippedResources: 2,
				},
			},
			inputPatterns: []string{"file.yaml", "file2.yaml"},
			expectedRow:   []string{"ctrl1", "5", "$ kubescape scan control ctrl1 file.yaml,file2.yaml -v"},
		},
		{
			name: "one file",
			controlSummary: reportsummary.ControlSummary{
				ControlID: "ctrl1",
				Name:      "ctrl1",
				StatusCounters: reportsummary.StatusCounters{
					FailedResources:  5,
					PassedResources:  3,
					SkippedResources: 2,
				},
			},
			inputPatterns: []string{"file.yaml"},
			expectedRow:   []string{"ctrl1", "5", "$ kubescape scan control ctrl1 file.yaml -v"},
		},
	}

	repoPrinter := NewRepoPrinter(nil)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			row := repoPrinter.generateCountingCategoryRow(&test.controlSummary, test.inputPatterns)

			if len(row) != len(test.expectedRow) {
				t.Errorf("expected row length %d, got %d", len(test.expectedRow), len(row))
			}

			for i := range row {
				if row[i] != test.expectedRow[i] {
					t.Errorf("expected row %v, got %v", test.expectedRow, row)
				}
			}
		})
	}

}

func TestRepoScan_GenerateTableNextSteps(t *testing.T) {
	tests := []struct {
		name              string
		controlSummary    reportsummary.ControlSummary
		expectedNextSteps string
		inputPatterns     []string
	}{
		{
			name: "single file",
			controlSummary: reportsummary.ControlSummary{
				ControlID: "ctrl1",
			},
			inputPatterns:     []string{"file.yaml"},
			expectedNextSteps: "$ kubescape scan control ctrl1 file.yaml -v",
		},
		{
			name: "multiple files",
			controlSummary: reportsummary.ControlSummary{
				ControlID: "ctrl1",
			},
			inputPatterns:     []string{"file.yaml", "file2.yaml"},
			expectedNextSteps: "$ kubescape scan control ctrl1 file.yaml,file2.yaml -v",
		},
	}

	repoPrinter := NewRepoPrinter(nil)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			nextSteps := repoPrinter.generateTableNextSteps(&test.controlSummary, test.inputPatterns)

			if nextSteps != test.expectedNextSteps {
				t.Errorf("expected next steps %s, got %s", test.expectedNextSteps, nextSteps)
			}
		})
	}
}
