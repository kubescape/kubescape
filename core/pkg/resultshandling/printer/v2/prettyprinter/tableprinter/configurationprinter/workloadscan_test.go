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

func TestWorkloadScan_InitCategoryTableData(t *testing.T) {
	tests := []struct {
		name           string
		categoryType   CategoryType
		expectedHeader []string
		expectedAlign  []int
	}{
		{
			name:           "status type",
			categoryType:   TypeStatus,
			expectedHeader: []string{"CONTROL NAME", "STATUS", "DOCS"},
			expectedAlign:  []int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER},
		},
		{
			name:           "counting type",
			categoryType:   TypeCounting,
			expectedHeader: []string{"CONTROL NAME", "RESOURCES", "RUN"},
			expectedAlign:  []int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_LEFT},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workloadPrinter := NewWorkloadPrinter()
			actualHeader, actualAlign := workloadPrinter.initCategoryTableData(tt.categoryType)

			for i := range actualHeader {
				assert.Equal(t, tt.expectedHeader[i], actualHeader[i])
			}

			for i := range actualAlign {
				assert.Equal(t, tt.expectedAlign[i], actualAlign[i])
			}
		})
	}
}

func TestWorkloadScan_GenerateCountingCategoryRow(t *testing.T) {
	tests := []struct {
		name           string
		controlSummary reportsummary.IControlSummary
		infoToPrint    []utils.InfoStars
		expectedRows   []string
	}{
		{
			name: "1 failed control",
			controlSummary: &reportsummary.ControlSummary{
				StatusInfo: apis.StatusInfo{
					InnerStatus: apis.StatusFailed,
				},
				ControlID: "ctrl1",
				Name:      "ctrl1",
				StatusCounters: reportsummary.StatusCounters{
					FailedResources: 1,
				},
			},
			expectedRows: []string{"ctrl1", "failed", "https://hub.armosec.io/docs/ctrl1"},
		},
		{
			name: "multiple failed controls",
			controlSummary: &reportsummary.ControlSummary{
				StatusInfo: apis.StatusInfo{
					InnerStatus: apis.StatusFailed,
				},
				ControlID: "ctrl1",
				Name:      "ctrl1",
				StatusCounters: reportsummary.StatusCounters{
					FailedResources: 5,
				},
			},
			expectedRows: []string{"ctrl1", "failed", "https://hub.armosec.io/docs/ctrl1"},
		},
		{
			name: "no failed controls",
			controlSummary: &reportsummary.ControlSummary{
				StatusInfo: apis.StatusInfo{
					InnerStatus: apis.StatusPassed,
				},
				ControlID: "ctrl1",
				Name:      "ctrl1",
				StatusCounters: reportsummary.StatusCounters{
					FailedResources: 0,
				},
			},
			expectedRows: []string{"ctrl1", "passed", "https://hub.armosec.io/docs/ctrl1"},
		},
		{
			name: "action required",
			infoToPrint: []utils.InfoStars{
				{
					Info:  "action required",
					Stars: "*",
				},
			},
			controlSummary: &reportsummary.ControlSummary{
				ControlID: "ctrl1",
				StatusInfo: apis.StatusInfo{
					InnerStatus: apis.StatusSkipped,
					InnerInfo:   "action required",
				},
				Name: "ctrl1",
				StatusCounters: reportsummary.StatusCounters{
					SkippedResources: 1,
				},
			},
			expectedRows: []string{"ctrl1", "action required *", "https://hub.armosec.io/docs/ctrl1"},
		},
	}

	workloadPrinter := NewWorkloadPrinter()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			row := workloadPrinter.generateCountingCategoryRow(tt.controlSummary, tt.infoToPrint)
			assert.True(t, reflect.DeepEqual(row, tt.expectedRows))
		})
	}
}
