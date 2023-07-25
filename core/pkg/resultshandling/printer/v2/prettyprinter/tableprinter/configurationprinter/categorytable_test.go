package configurationprinter

import (
	"reflect"
	"testing"

	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/olekukonko/tablewriter"
	"github.com/stretchr/testify/assert"
)

func Test_initCategoryTableData(t *testing.T) {
	tests := []struct {
		name               string
		categoryType       CategoryType
		expectedHeaders    []string
		expectedAlignments []int
	}{
		{
			name:               "Test1",
			categoryType:       TypeCounting,
			expectedHeaders:    []string{"CONTROL NAME", "RESOURCES", "RUN"},
			expectedAlignments: []int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_LEFT},
		},
		{
			name:               "Test2",
			categoryType:       TypeStatus,
			expectedHeaders:    []string{"CONTROL NAME", "STATUS", "DOCS"},
			expectedAlignments: []int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers, alignments := initCategoryTableData(tt.categoryType)
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

func Test_generateCategoryStatusRow(t *testing.T) {
	tests := []struct {
		name            string
		controlSummary  reportsummary.IControlSummary
		infoToPrintInfo []utils.InfoStars
		expectedRows    []string
	}{
		{
			name: "failed control",
			controlSummary: &reportsummary.ControlSummary{
				Name:      "test",
				Status:    apis.StatusFailed,
				ControlID: "ctrlID",
			},
			expectedRows: []string{"test", "failed", "https://hub.armosec.io/docs/ctrlid"},
		},
		{
			name: "skipped control",
			controlSummary: &reportsummary.ControlSummary{
				Name:   "test",
				Status: apis.StatusSkipped,
				StatusInfo: apis.StatusInfo{
					InnerInfo: "testInfo",
				},
				ControlID: "ctrlID",
			},
			expectedRows: []string{"test", "action required *", "https://hub.armosec.io/docs/ctrlid"},
			infoToPrintInfo: []utils.InfoStars{
				{
					Info:  "testInfo",
					Stars: "*",
				},
			},
		},
		{
			name: "passed control",
			controlSummary: &reportsummary.ControlSummary{
				Name:      "test",
				Status:    apis.StatusPassed,
				ControlID: "ctrlID",
			},
			expectedRows: []string{"test", "passed", "https://hub.armosec.io/docs/ctrlid"},
		},
		{
			name: "big name",
			controlSummary: &reportsummary.ControlSummary{
				Name:      "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest",
				Status:    apis.StatusFailed,
				ControlID: "ctrlID",
			},
			expectedRows: []string{"testtesttesttesttesttesttesttesttesttesttesttestte...", "failed", "https://hub.armosec.io/docs/ctrlid"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			row := generateCategoryStatusRow(tt.controlSummary, tt.infoToPrintInfo)
			assert.True(t, reflect.DeepEqual(row, tt.expectedRows))
		})
	}
}
