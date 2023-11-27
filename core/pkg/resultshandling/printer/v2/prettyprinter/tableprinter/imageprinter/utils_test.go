package imageprinter

import (
	"io"
	"os"
	"testing"

	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/olekukonko/tablewriter"
	"github.com/stretchr/testify/assert"
)

func TestRenderTable(t *testing.T) {
	headers := getImageScanningHeaders()
	columnAlignments := getImageScanningColumnsAlignments()

	test := []struct {
		name    string
		summary ImageScanSummary
		want    string
	}{
		{
			name: "check CVEs are sorted by severity",
			summary: ImageScanSummary{
				CVEs: []CVE{
					{
						ID:         "CVE-2020-0001",
						Severity:   "Low",
						Package:    "package1",
						Version:    "1.0.0",
						FixedState: string(v5.NotFixedState),
					},
					{
						ID:         "CVE-2020-0002",
						Severity:   "High",
						Package:    "package2",
						Version:    "1.0.0",
						FixedState: string(v5.NotFixedState),
					},
					{
						ID:         "CVE-2020-0003",
						Severity:   "Medium",
						Package:    "package3",
						Version:    "1.0.0",
						FixedState: string(v5.NotFixedState),
					},
				},
			},
			want: "┌──────────┬───────────────┬───────────┬─────────┬──────────┐\n│ Severity │ Vulnerability │ Component │ Version │ Fixed in │\n├──────────┼───────────────┼───────────┼─────────┼──────────┤\n│   High   │ CVE-2020-0002 │ package2  │ 1.0.0   │          │\n│  Medium  │ CVE-2020-0003 │ package3  │ 1.0.0   │          │\n│   Low    │ CVE-2020-0001 │ package1  │ 1.0.0   │          │\n└──────────┴───────────────┴───────────┴─────────┴──────────┘\n",
		},
		{
			name: "check fixed CVEs show versions",
			summary: ImageScanSummary{
				CVEs: []CVE{
					{
						ID:         "CVE-2020-0001",
						Severity:   "Low",
						Package:    "package1",
						Version:    "1.0.0",
						FixedState: string(v5.NotFixedState),
					},
					{
						ID:          "CVE-2020-0002",
						Severity:    "High",
						Package:     "package2",
						Version:     "1.0.0",
						FixVersions: []string{"v1", "v2"},
						FixedState:  string(v5.FixedState),
					},
				},
			},
			want: "┌──────────┬───────────────┬───────────┬─────────┬──────────┐\n│ Severity │ Vulnerability │ Component │ Version │ Fixed in │\n├──────────┼───────────────┼───────────┼─────────┼──────────┤\n│   High   │ CVE-2020-0002 │ package2  │ 1.0.0   │ v1,v2    │\n│   Low    │ CVE-2020-0001 │ package1  │ 1.0.0   │          │\n└──────────┴───────────────┴───────────┴─────────┴──────────┘\n",
		},
	}

	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			rows := generateRows(tt.summary)

			// Create a temporary file to capture output
			f, err := os.CreateTemp("", "print-next-steps")
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

			renderTable(f, headers, columnAlignments, rows)

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

func TestGenerateRows(t *testing.T) {
	test := []struct {
		name         string
		summary      ImageScanSummary
		expectedRows [][]string
	}{
		{
			name: "check CVEs are sorted by severity",
			summary: ImageScanSummary{
				CVEs: []CVE{
					{
						ID:         "CVE-2020-0001",
						Severity:   "Low",
						Package:    "package1",
						Version:    "1.0.0",
						FixedState: string(v5.NotFixedState),
					},
					{
						ID:         "CVE-2020-0002",
						Severity:   "High",
						Package:    "package2",
						Version:    "1.0.0",
						FixedState: string(v5.NotFixedState),
					},
					{
						ID:         "CVE-2020-0003",
						Severity:   "Medium",
						Package:    "package3",
						Version:    "1.0.0",
						FixedState: string(v5.NotFixedState),
					},
				},
			},
			expectedRows: [][]string{
				{"High", "CVE-2020-0002", "package2", "1.0.0", ""},
				{"Medium", "CVE-2020-0003", "package3", "1.0.0", ""},
				{"Low", "CVE-2020-0001", "package1", "1.0.0", ""},
			},
		},
		{
			name: "check fixed CVEs show versions",
			summary: ImageScanSummary{
				CVEs: []CVE{
					{
						ID:         "CVE-2020-0001",
						Severity:   "Low",
						Package:    "package1",
						Version:    "1.0.0",
						FixedState: string(v5.NotFixedState),
					},
					{
						ID:          "CVE-2020-0002",
						Severity:    "High",
						Package:     "package2",
						Version:     "1.0.0",
						FixVersions: []string{"v1", "v2"},
						FixedState:  string(v5.FixedState),
					},
				},
			},
			expectedRows: [][]string{
				{"High", "CVE-2020-0002", "package2", "1.0.0", "v1,v2"},
				{"Low", "CVE-2020-0001", "package1", "1.0.0", ""},
			},
		},
	}

	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			actualRows := generateRows(tt.summary)
			if len(actualRows) != len(tt.expectedRows) {
				t.Errorf("expected %d rows, got %d", len(tt.expectedRows), len(actualRows))
			}

			for i := range actualRows {
				for j := range actualRows[i] {
					if actualRows[i][j] != tt.expectedRows[i][j] {
						t.Errorf("expected %s, got %s", tt.expectedRows[i][j], actualRows[i][j])
					}
				}
			}
		})

	}
}

func TestGenerateRow(t *testing.T) {
	tests := []struct {
		name string
		cve  CVE
		want []string
	}{
		{
			name: "check row with fixed version",
			cve: CVE{
				Severity:    "High",
				ID:          "CVE-2020-0001",
				Package:     "package1",
				Version:     "1.0.0",
				FixVersions: []string{"v1", "v2"},
				FixedState:  string(v5.FixedState),
			},
			want: []string{"High", "CVE-2020-0001", "package1", "1.0.0", "v1,v2"},
		},
		{
			name: "check row with not fixed version",
			cve: CVE{
				Severity:   "High",
				ID:         "CVE-2020-0001",
				Package:    "package1",
				Version:    "1.0.0",
				FixedState: string(v5.NotFixedState),
			},
			want: []string{"High", "CVE-2020-0001", "package1", "1.0.0", ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualRow := generateRow(tt.cve)
			for i := range actualRow {
				if actualRow[i] != tt.want[i] {
					t.Errorf("expected %s, got %s", tt.want[i], actualRow[i])
				}
			}

		})
	}
}

func TestGetImageScanningHeaders(t *testing.T) {
	headers := getImageScanningHeaders()

	expectedHeaders := []string{"Severity", "Vulnerability", "Component", "Version", "Fixed in"}

	for i := range headers {
		if headers[i] != expectedHeaders[i] {
			t.Errorf("expected %s, got %s", expectedHeaders[i], headers[i])
		}
	}
}

func TestGetImageScanningColumnsAlignments(t *testing.T) {
	alignments := getImageScanningColumnsAlignments()

	expectedAlignments := []int{tablewriter.ALIGN_CENTER, tablewriter.ALIGN_LEFT, tablewriter.ALIGN_LEFT, tablewriter.ALIGN_LEFT, tablewriter.ALIGN_LEFT}

	for i := range alignments {
		if alignments[i] != expectedAlignments[i] {
			t.Errorf("expected %d, got %d", expectedAlignments[i], alignments[i])
		}
	}
}
