package configurationprinter

import (
	"testing"

	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"

	"github.com/stretchr/testify/assert"
)

func TestClusterScan_GenerateCountingCategoryRow(t *testing.T) {
	tests := []struct {
		name           string
		controlSummary reportsummary.IControlSummary
		expectedRow    []string
	}{
		{
			name: "failed resources",
			controlSummary: &reportsummary.ControlSummary{
				ControlID: "ctrl1",
				Name:      "ctrl1",
				StatusCounters: reportsummary.StatusCounters{
					FailedResources:  5,
					PassedResources:  3,
					SkippedResources: 2,
				},
			},
			expectedRow: []string{"ctrl1", "5", "$ kubescape scan control ctrl1 -v"},
		},
		{
			name: "passed resources",
			controlSummary: &reportsummary.ControlSummary{
				ControlID: "ctrl2",
				Name:      "ctrl2",
				StatusCounters: reportsummary.StatusCounters{
					PassedResources: 3,
				},
			},
			expectedRow: []string{"ctrl2", "0", "$ kubescape scan control ctrl2 -v"},
		},
	}

	clusterPrinter := NewClusterPrinter()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			row := clusterPrinter.generateCountingCategoryRow(test.controlSummary)

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

func TestClusterScan_GenerateTableNextSteps(t *testing.T) {
	tests := []struct {
		name              string
		controlSummary    reportsummary.IControlSummary
		expectedNextSteps string
	}{
		{
			name: "with id",
			controlSummary: &reportsummary.ControlSummary{
				ControlID: "ctrl1",
			},
			expectedNextSteps: "$ kubescape scan control ctrl1 -v",
		}, {
			name:              "empty id",
			controlSummary:    &reportsummary.ControlSummary{},
			expectedNextSteps: "$ kubescape scan control  -v",
		},
	}

	clusterPrinter := NewClusterPrinter()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			nextSteps := clusterPrinter.generateTableNextSteps(test.controlSummary)

			if nextSteps != test.expectedNextSteps {
				t.Errorf("expected next steps %s, got %s", test.expectedNextSteps, nextSteps)
			}
		})
	}
}

func TestNewClusterPrinter(t *testing.T) {
	cp := NewClusterPrinter()
	assert.NotNil(t, cp)
}

func TestClusterPrinter_PrintSummaryTable_NoOp(t *testing.T) {
	cp := NewClusterPrinter()
	assert.NotPanics(t, func() {
		cp.PrintSummaryTable(nil, nil, nil)
	}, "PrintSummaryTable should be a no-op and never panic")
}
