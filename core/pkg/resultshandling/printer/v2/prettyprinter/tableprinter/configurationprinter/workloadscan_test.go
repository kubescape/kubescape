package configurationprinter

import (
	"reflect"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/olekukonko/tablewriter"
	"github.com/stretchr/testify/assert"
)

func TestWorkloadScan_InitCategoryTableData(t *testing.T) {
	tests := []struct {
		name               string
		categoryType       CategoryType
		expectedHeaders    []string
		expectedAlignments []int
	}{
		{
			name:               "Test1",
			categoryType:       TypeCounting,
			expectedHeaders:    []string{"CONTROL NAME", "RESOURCES"},
			expectedAlignments: []int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER},
		},
		{
			name:               "Test2",
			categoryType:       TypeStatus,
			expectedHeaders:    []string{"CONTROL NAME", "STATUS", "DOCS"},
			expectedAlignments: []int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER},
		},
	}

	workloadPrinter := NewWorkloadPrinter()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers, alignments := workloadPrinter.initCategoryTableData(tt.categoryType)
			if len(headers) != len(tt.expectedHeaders) {
				t.Errorf("initCategoryTableData() headers = %v, want %v", headers, tt.expectedHeaders)
			}
			if len(alignments) != len(tt.expectedAlignments) {
				t.Errorf("initCategoryTableData() alignments = %v, want %v", alignments, tt.expectedAlignments)
			}
			assert.True(t, reflect.DeepEqual(headers, tt.expectedHeaders))
			assert.True(t, reflect.DeepEqual(alignments, tt.expectedAlignments))
		})
	}
}

func TestWorkloadScan_GenerateCountingCategoryRow(t *testing.T) {
	tests := []struct {
		name           string
		controlSummary reportsummary.IControlSummary
		expectedRows   []string
	}{
		{
			name: "1 failed control",
			controlSummary: &reportsummary.ControlSummary{
				Name: "ctrl1",
				StatusCounters: reportsummary.StatusCounters{
					FailedResources: 1,
				},
			},
			expectedRows: []string{"ctrl1", "1"},
		},
		{
			name: "multiple failed controls",
			controlSummary: &reportsummary.ControlSummary{
				Name: "ctrl1",
				StatusCounters: reportsummary.StatusCounters{
					FailedResources: 5,
				},
			},
			expectedRows: []string{"ctrl1", "5"},
		},
		{
			name: "no failed controls",
			controlSummary: &reportsummary.ControlSummary{
				Name: "ctrl1",
				StatusCounters: reportsummary.StatusCounters{
					FailedResources: 0,
				},
			},
			expectedRows: []string{"ctrl1", "0"},
		},
	}

	workloadPrinter := NewWorkloadPrinter()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			row := workloadPrinter.generateCountingCategoryRow(tt.controlSummary)
			assert.True(t, reflect.DeepEqual(row, tt.expectedRows))
		})
	}
}

func TestWorkloadScan_GetCategoryCountingTypeHeaders(t *testing.T) {

	workloadPrinter := NewWorkloadPrinter()

	headers := workloadPrinter.getCategoryCountingTypeHeaders()

	assert.True(t, reflect.DeepEqual(headers, []string{"CONTROL NAME", "RESOURCES"}))

}

func TestWorkloadScan_GetCountingTypeAlignments(t *testing.T) {

	workloadPrinter := NewWorkloadPrinter()

	alignments := workloadPrinter.getCountingTypeAlignments()

	assert.True(t, reflect.DeepEqual(alignments, []int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER}))

}
