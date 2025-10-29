package configurationprinter

import (
	"io"
	"os"
	"testing"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/stretchr/testify/assert"
)

func TestInitCategoryTableData(t *testing.T) {
	tests := []struct {
		name               string
		categoryType       CategoryType
		expectedHeaders    table.Row
		expectedAlignments []table.ColumnConfig
	}{
		{
			name:               "Test1",
			categoryType:       TypeCounting,
			expectedHeaders:    table.Row{"Control name", "Resources", "View details"},
			expectedAlignments: []table.ColumnConfig{{Number: 1, Align: text.AlignLeft}, {Number: 2, Align: text.AlignCenter}, {Number: 3, Align: text.AlignLeft}},
		},
		{
			name:               "Test2",
			categoryType:       TypeStatus,
			expectedHeaders:    table.Row{"", "Control name", "Docs"},
			expectedAlignments: []table.ColumnConfig{{Number: 1, Align: text.AlignCenter}, {Number: 2, Align: text.AlignLeft}, {Number: 3, Align: text.AlignCenter}},
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
			assert.Equal(t, headers, tt.expectedHeaders)
			assert.Equal(t, alignments, tt.expectedAlignments)
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

func TestGenerateCategoryStatusRow(t *testing.T) {
	tests := []struct {
		name            string
		controlSummary  reportsummary.IControlSummary
		infoToPrintInfo []utils.InfoStars
		expectedRows    table.Row
	}{
		{
			name: "failed control",
			controlSummary: &reportsummary.ControlSummary{
				Name:      "test",
				Status:    apis.StatusFailed,
				ControlID: "ctrlID",
			},
			expectedRows: table.Row{"❌", "test", "https://kubescape.io/docs/controls/ctrlid"},
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
			expectedRows: table.Row{"⚠️", "test", "https://kubescape.io/docs/controls/ctrlid"},
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
			expectedRows: table.Row{"✅", "test", "https://kubescape.io/docs/controls/ctrlid"},
		},
		{
			name: "big name",
			controlSummary: &reportsummary.ControlSummary{
				Name:      "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest",
				Status:    apis.StatusFailed,
				ControlID: "ctrlID",
			},
			expectedRows: table.Row{"❌", "testtesttesttesttesttesttesttesttesttesttesttestte...", "https://kubescape.io/docs/controls/ctrlid"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			row := generateCategoryStatusRow(tt.controlSummary)
			assert.Equal(t, tt.expectedRows, row)
		})
	}
}

func TestGetCategoryTableWriter(t *testing.T) {
	tests := []struct {
		name             string
		headers          table.Row
		columnAlignments []table.ColumnConfig
		want             string
	}{
		{
			name:             "Test1",
			headers:          table.Row{"Control name", "Resources", "View details"},
			columnAlignments: []table.ColumnConfig{{Number: 1, Align: text.AlignLeft}, {Number: 2, Align: text.AlignCenter}, {Number: 3, Align: text.AlignLeft}},
			want:             "╭──────────────┬───────────┬──────────────╮\n│ Control name │ Resources │ View details │\n├──────────────┼───────────┼──────────────┤\n╰──────────────┴───────────┴──────────────╯\n",
		},
		{
			name:             "Test2",
			headers:          table.Row{"", "Control name", "Docs"},
			columnAlignments: []table.ColumnConfig{{Number: 1, Align: text.AlignCenter}, {Number: 2, Align: text.AlignLeft}, {Number: 3, Align: text.AlignCenter}},
			want:             "╭──┬──────────────┬──────╮\n│  │ Control name │ Docs │\n├──┼──────────────┼──────┤\n╰──┴──────────────┴──────╯\n",
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

			tableWriter := getCategoryTableWriter(f, tt.headers, tt.columnAlignments)

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
		name             string
		categoryName     string
		rows             []table.Row
		infoToPrintInfo  []utils.InfoStars
		headers          table.Row
		columnAlignments []table.ColumnConfig
		want             string
	}{
		{
			name:         "Test1",
			categoryName: "Resources",
			rows: []table.Row{
				{"Regular", "regular line", "1"},
				{"Thick", "particularly thick line", "2"},
				{"Double", "double line", "3"},
			},
			infoToPrintInfo: []utils.InfoStars{
				{
					Stars: "1",
					Info:  "Low severity",
				},
				{
					Stars: "5",
					Info:  "Critical severity",
				},
			},
			headers:          table.Row{"Control name", "Resources", "View details"},
			columnAlignments: []table.ColumnConfig{{Number: 1, Align: text.AlignLeft}, {Number: 2, Align: text.AlignCenter}, {Number: 3, Align: text.AlignLeft}},
			want:             "Resources\n╭──────────────┬─────────────────────────┬──────────────╮\n│ Control name │ Resources               │ View details │\n├──────────────┼─────────────────────────┼──────────────┤\n│ Regular      │       regular line      │ 1            │\n│ Thick        │ particularly thick line │ 2            │\n│ Double       │       double line       │ 3            │\n╰──────────────┴─────────────────────────┴──────────────╯\n1 Low severity\n5 Critical severity\n\n",
		},
		{
			name:         "Test2",
			categoryName: "Control name",
			rows: []table.Row{
				{"Regular", "regular line", "1"},
				{"Thick", "particularly thick line", "2"},
				{"Double", "double line", "3"},
			},
			infoToPrintInfo: []utils.InfoStars{
				{
					Stars: "1",
					Info:  "Low severity",
				},
				{
					Stars: "5",
					Info:  "Critical severity",
				},
				{
					Stars: "4",
					Info:  "High severity",
				},
			},
			headers:          table.Row{"Control name", "Resources", "View details"},
			columnAlignments: []table.ColumnConfig{{Number: 1, Align: text.AlignLeft}, {Number: 2, Align: text.AlignCenter}, {Number: 3, Align: text.AlignLeft}},
			want:             "Control name\n╭──────────────┬─────────────────────────┬──────────────╮\n│ Control name │ Resources               │ View details │\n├──────────────┼─────────────────────────┼──────────────┤\n│ Regular      │       regular line      │ 1            │\n│ Thick        │ particularly thick line │ 2            │\n│ Double       │       double line       │ 3            │\n╰──────────────┴─────────────────────────┴──────────────╯\n1 Low severity\n5 Critical severity\n4 High severity\n\n",
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

			tableWriter := getCategoryTableWriter(f, tt.headers, tt.columnAlignments)

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
