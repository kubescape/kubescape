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

func TestInitCategoryTableData(t *testing.T) {
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

func TestGetCategoryStatusTypeHeaders(t *testing.T) {
	headers := getCategoryStatusTypeHeaders()

	if len(headers) != 3 {
		t.Errorf("Expected 3 headers, got %d", len(headers))
	}

	if headers[0] != controlNameHeader {
		t.Errorf("Expected %s, got %s", controlNameHeader, headers[0])
	}

	if headers[1] != statusHeader {
		t.Errorf("Expected %s, got %s", statusHeader, headers[1])
	}

	if headers[2] != docsHeader {
		t.Errorf("Expected %s, got %s", docsHeader, headers[2])
	}
}

func TestGetCategoryCountingTypeHeaders(t *testing.T) {
	headers := getCategoryCountingTypeHeaders()

	if len(headers) != 3 {
		t.Errorf("Expected 3 headers, got %d", len(headers))
	}

	if headers[0] != controlNameHeader {
		t.Errorf("Expected %s, got %s", controlNameHeader, headers[0])
	}

	if headers[1] != resourcesHeader {
		t.Errorf("Expected %s, got %s", resourcesHeader, headers[1])
	}

	if headers[2] != runHeader {
		t.Errorf("Expected %s, got %s", runHeader, headers[2])
	}
}

func TestGetStatusTypeAlignments(t *testing.T) {
	alignments := getStatusTypeAlignments()

	if len(alignments) != 3 {
		t.Errorf("Expected 3 alignments, got %d", len(alignments))
	}

	if alignments[0] != tablewriter.ALIGN_LEFT {
		t.Errorf("Expected %d, got %d", tablewriter.ALIGN_LEFT, alignments[0])
	}

	if alignments[1] != tablewriter.ALIGN_CENTER {
		t.Errorf("Expected %d, got %d", tablewriter.ALIGN_CENTER, alignments[1])
	}

	if alignments[2] != tablewriter.ALIGN_CENTER {
		t.Errorf("Expected %d, got %d", tablewriter.ALIGN_CENTER, alignments[2])
	}
}

func TestGetCountingTypeAlignments(t *testing.T) {
	alignments := getCountingTypeAlignments()

	if len(alignments) != 3 {
		t.Errorf("Expected 3 alignments, got %d", len(alignments))
	}

	if alignments[0] != tablewriter.ALIGN_LEFT {
		t.Errorf("Expected %d, got %d", tablewriter.ALIGN_LEFT, alignments[0])
	}

	if alignments[1] != tablewriter.ALIGN_CENTER {
		t.Errorf("Expected %d, got %d", tablewriter.ALIGN_CENTER, alignments[1])
	}

	if alignments[2] != tablewriter.ALIGN_LEFT {
		t.Errorf("Expected %d, got %d", tablewriter.ALIGN_LEFT, alignments[2])
	}
}

func TestGenerateCategoryStatusRow(t *testing.T) {
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
