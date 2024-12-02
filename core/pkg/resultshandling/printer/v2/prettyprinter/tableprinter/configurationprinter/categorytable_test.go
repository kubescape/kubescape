package configurationprinter

import (
	"io"
	"os"
	"reflect"
	"testing"

	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
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
			expectedHeaders:    []string{"Control name", "Resources", "View details"},
			expectedAlignments: []int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_LEFT},
		},
		{
			name:               "Test2",
			categoryType:       TypeStatus,
			expectedHeaders:    []string{"", "Control name", "Docs"},
			expectedAlignments: []int{tablewriter.ALIGN_CENTER, tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER},
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

	if headers[0] != statusHeader {
		t.Errorf("Expected %s, got %s", statusHeader, headers[0])
	}

	if headers[1] != controlNameHeader {
		t.Errorf("Expected %s, got %s", controlNameHeader, headers[1])
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

	if alignments[0] != tablewriter.ALIGN_CENTER {
		t.Errorf("Expected %d, got %d", tablewriter.ALIGN_CENTER, alignments[0])
	}

	if alignments[1] != tablewriter.ALIGN_LEFT {
		t.Errorf("Expected %d, got %d", tablewriter.ALIGN_LEFT, alignments[1])
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
			expectedRows: []string{"❌", "test", "https://hub.armosec.io/docs/ctrlid"},
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
			expectedRows: []string{"⚠️", "test", "https://hub.armosec.io/docs/ctrlid"},
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
			expectedRows: []string{"✅", "test", "https://hub.armosec.io/docs/ctrlid"},
		},
		{
			name: "big name",
			controlSummary: &reportsummary.ControlSummary{
				Name:      "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest",
				Status:    apis.StatusFailed,
				ControlID: "ctrlID",
			},
			expectedRows: []string{"❌", "testtesttesttesttesttesttesttesttesttesttesttestte...", "https://hub.armosec.io/docs/ctrlid"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			row := generateCategoryStatusRow(tt.controlSummary, tt.infoToPrintInfo)
			assert.True(t, reflect.DeepEqual(row, tt.expectedRows))
		})
	}
}

func TestGetCategoryTableWriter(t *testing.T) {
	tests := []struct {
		name            string
		headers         []string
		columnAligments []int
		want            string
	}{
		{
			name:            "Test1",
			headers:         []string{"Control name", "Resources", "View details"},
			columnAligments: []int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_LEFT},
			want:            "┌──────────────┬───────────┬──────────────┐\n│ Control name │ Resources │ View details │\n├──────────────┼───────────┼──────────────┤\n└──────────────┴───────────┴──────────────┘\n",
		},
		{
			name:            "Test2",
			headers:         []string{"", "Control name", "Docs"},
			columnAligments: []int{tablewriter.ALIGN_CENTER, tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER},
			want:            "┌──┬──────────────┬──────┐\n│  │ Control name │ Docs │\n├──┼──────────────┼──────┤\n└──┴──────────────┴──────┘\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary file to capture output
			f, err := os.CreateTemp("", "print")
			if err != nil {
				panic(err)
			}
			defer f.Close()

			tableWriter := getCategoryTableWriter(f, tt.headers, tt.columnAligments)

			// Redirect stderr to the temporary file
			oldStderr := os.Stderr
			defer func() {
				os.Stderr = oldStderr
			}()
			os.Stderr = f

			tableWriter.Render()

			// Read the contents of the temporary file
			f.Seek(0, 0)
			got, err := io.ReadAll(f)
			if err != nil {
				panic(err)
			}

			assert.NotNil(t, tableWriter)
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestRenderSingleCategory(t *testing.T) {
	tests := []struct {
		name            string
		categoryName    string
		rows            [][]string
		infoToPrintInfo []utils.InfoStars
		headers         []string
		columnAligments []int
		want            string
	}{
		{
			name:         "Test1",
			categoryName: "Resources",
			rows: [][]string{
				{"Regular", "regular line", "1"},
				{"Thick", "particularly thick line", "2"},
				{"Double", "double line", "3"},
			},
			infoToPrintInfo: []utils.InfoStars{
				utils.InfoStars{
					Stars: "1",
					Info:  "Low severity",
				},
				utils.InfoStars{
					Stars: "5",
					Info:  "Critical severity",
				},
			},
			headers:         []string{"Control name", "Resources", "View details"},
			columnAligments: []int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_LEFT},
			want:            "Resources\n┌──────────────┬─────────────────────────┬──────────────┐\n│ Control name │ Resources               │ View details │\n├──────────────┼─────────────────────────┼──────────────┤\n│ Regular      │      regular line       │ 1            │\n│ Thick        │ particularly thick line │ 2            │\n│ Double       │       double line       │ 3            │\n└──────────────┴─────────────────────────┴──────────────┘\n1 Low severity\n5 Critical severity\n\n",
		},
		{
			name:         "Test2",
			categoryName: "Control name",
			rows: [][]string{
				{"Regular", "regular line", "1"},
				{"Thick", "particularly thick line", "2"},
				{"Double", "double line", "3"},
			},
			infoToPrintInfo: []utils.InfoStars{
				utils.InfoStars{
					Stars: "1",
					Info:  "Low severity",
				},
				utils.InfoStars{
					Stars: "5",
					Info:  "Critical severity",
				},
				utils.InfoStars{
					Stars: "4",
					Info:  "High severity",
				},
			},
			headers:         []string{"Control name", "Resources", "View details"},
			columnAligments: []int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_LEFT},
			want:            "Control name\n┌──────────────┬─────────────────────────┬──────────────┐\n│ Control name │ Resources               │ View details │\n├──────────────┼─────────────────────────┼──────────────┤\n│ Regular      │      regular line       │ 1            │\n│ Thick        │ particularly thick line │ 2            │\n│ Double       │       double line       │ 3            │\n└──────────────┴─────────────────────────┴──────────────┘\n1 Low severity\n5 Critical severity\n4 High severity\n\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary file to capture output
			f, err := os.CreateTemp("", "print")
			if err != nil {
				panic(err)
			}
			defer f.Close()

			tableWriter := getCategoryTableWriter(f, tt.headers, tt.columnAligments)

			// Redirect stderr to the temporary file
			oldStderr := os.Stderr
			defer func() {
				os.Stderr = oldStderr
			}()
			os.Stderr = f

			renderSingleCategory(f, tt.categoryName, tableWriter, tt.rows, tt.infoToPrintInfo)

			// Read the contents of the temporary file
			f.Seek(0, 0)
			got, err := io.ReadAll(f)
			if err != nil {
				panic(err)
			}

			assert.NotNil(t, tableWriter)
			assert.Equal(t, tt.want, string(got))
		})
	}
}
