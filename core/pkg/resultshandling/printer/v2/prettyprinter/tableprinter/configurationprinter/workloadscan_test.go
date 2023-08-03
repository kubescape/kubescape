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

	expectedHeader := []string{"CONTROL NAME", "STATUS", "DOCS"}
	expectedAlign := []int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER}

	workloadPrinter := NewWorkloadPrinter()

	headers, columnAligments := workloadPrinter.initCategoryTableData()

	for i := range headers {
		if headers[i] != expectedHeader[i] {
			t.Errorf("Expected header %s, got %s", expectedHeader[i], headers[i])
		}
	}

	for i := range columnAligments {
		if columnAligments[i] != expectedAlign[i] {
			t.Errorf("Expected column alignment %d, got %d", expectedAlign[i], columnAligments[i])
		}
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
