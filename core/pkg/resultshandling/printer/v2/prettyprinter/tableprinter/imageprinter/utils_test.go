package imageprinter

import (
	"io"
	"os"
	"testing"

	v5 "github.com/anchore/grype/grype/db/v5"
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
						Image:      "nginx:latest",
					},
					{
						ID:         "CVE-2020-0002",
						Severity:   "High",
						Package:    "package2",
						Version:    "1.0.0",
						FixedState: string(v5.NotFixedState),
						Image:      "alpine:3.18",
					},
					{
						ID:         "CVE-2020-0003",
						Severity:   "Medium",
						Package:    "package3",
						Version:    "1.0.0",
						FixedState: string(v5.NotFixedState),
						Image:      "ubuntu:22.04",
					},
				},
			},
			want: "╭──────────┬───────────────┬───────────┬─────────┬──────────┬──────────────╮\n│ Severity │ Vulnerability │ Component │ Version │ Fixed in │ Image        │\n├──────────┼───────────────┼───────────┼─────────┼──────────┼──────────────┤\n│   High   │ CVE-2020-0002 │ package2  │ 1.0.0   │          │ alpine:3.18  │\n│  Medium  │ CVE-2020-0003 │ package3  │ 1.0.0   │          │ ubuntu:22.04 │\n│    Low   │ CVE-2020-0001 │ package1  │ 1.0.0   │          │ nginx:latest │\n╰──────────┴───────────────┴───────────┴─────────┴──────────┴──────────────╯\n",
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
						Image:      "test:latest",
					},
					{
						ID:          "CVE-2020-0002",
						Severity:    "High",
						Package:     "package2",
						Version:     "1.0.0",
						FixVersions: []string{"v1", "v2"},
						FixedState:  string(v5.FixedState),
						Image:       "golang:1.24",
					},
				},
			},
			want: "╭──────────┬───────────────┬───────────┬─────────┬──────────┬─────────────╮\n│ Severity │ Vulnerability │ Component │ Version │ Fixed in │ Image       │\n├──────────┼───────────────┼───────────┼─────────┼──────────┼─────────────┤\n│   High   │ CVE-2020-0002 │ package2  │ 1.0.0   │ v1,v2    │ golang:1.24 │\n│    Low   │ CVE-2020-0001 │ package1  │ 1.0.0   │          │ test:latest │\n╰──────────┴───────────────┴───────────┴─────────┴──────────┴─────────────╯\n",
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
						Image:      "nginx:latest",
					},
					{
						ID:         "CVE-2020-0002",
						Severity:   "High",
						Package:    "package2",
						Version:    "1.0.0",
						FixedState: string(v5.NotFixedState),
						Image:      "alpine:3.18",
					},
					{
						ID:         "CVE-2020-0003",
						Severity:   "Medium",
						Package:    "package3",
						Version:    "1.0.0",
						FixedState: string(v5.NotFixedState),
						Image:      "ubuntu:22.04",
					},
				},
			},
			expectedRows: [][]string{
				{"High", "CVE-2020-0002", "package2", "1.0.0", "", "alpine:3.18"},
				{"Medium", "CVE-2020-0003", "package3", "1.0.0", "", "ubuntu:22.04"},
				{"Low", "CVE-2020-0001", "package1", "1.0.0", "", "nginx:latest"},
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
						Image:      "test:latest",
					},
					{
						ID:          "CVE-2020-0002",
						Severity:    "High",
						Package:     "package2",
						Version:     "1.0.0",
						FixVersions: []string{"v1", "v2"},
						FixedState:  string(v5.FixedState),
						Image:       "golang:1.24",
					},
				},
			},
			expectedRows: [][]string{
				{"High", "CVE-2020-0002", "package2", "1.0.0", "v1,v2", "golang:1.24"},
				{"Low", "CVE-2020-0001", "package1", "1.0.0", "", "test:latest"},
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
				Image:       "golang:1.24",
			},
			want: []string{"High", "CVE-2020-0001", "package1", "1.0.0", "v1,v2", "golang:1.24"},
		},
		{
			name: "check row with not fixed version",
			cve: CVE{
				Severity:   "High",
				ID:         "CVE-2020-0001",
				Package:    "package1",
				Version:    "1.0.0",
				FixedState: string(v5.NotFixedState),
				Image:      "nginx:latest",
			},
			want: []string{"High", "CVE-2020-0001", "package1", "1.0.0", "", "nginx:latest"},
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

	expectedHeaders := []string{"Severity", "Vulnerability", "Component", "Version", "Fixed in", "Image"}

	for i := range headers {
		if headers[i] != expectedHeaders[i] {
			t.Errorf("expected %s, got %s", expectedHeaders[i], headers[i])
		}
	}
}

func TestGenerateRows_AppendsVEXColumnsWhenPresent(t *testing.T) {
	summary := ImageScanSummary{
		CVEs: []CVE{
			{
				ID:         "CVE-2020-0001",
				Severity:   "Low",
				Package:    "package1",
				Version:    "1.0.0",
				FixedState: string(v5.NotFixedState),
				Image:      "nginx:latest",
			},
			{
				ID:               "CVE-2020-0002",
				Severity:         "High",
				Package:          "package2",
				Version:          "1.0.0",
				FixedState:       string(v5.NotFixedState),
				Image:            "alpine:3.18",
				VexStatus:        "not_affected",
				VexJustification: "component_not_present",
			},
		},
	}

	rows := generateRows(summary)

	assert.Equal(t, []string{
		"High",
		"CVE-2020-0002",
		"package2",
		"1.0.0",
		"",
		"alpine:3.18",
		"not_affected",
		"component_not_present",
	}, rowToStrings(rows[0]))
	assert.Equal(t, []string{
		"Low",
		"CVE-2020-0001",
		"package1",
		"1.0.0",
		"",
		"nginx:latest",
		"",
		"",
	}, rowToStrings(rows[1]))
}

func TestRenderTable_WithVEXColumns(t *testing.T) {
	summary := ImageScanSummary{
		CVEs: []CVE{
			{
				ID:               "CVE-2020-0004",
				Severity:         "High",
				Package:          "package4",
				Version:          "1.0.0",
				FixedState:       string(v5.NotFixedState),
				Image:            "alpine:3.18",
				VexStatus:        "not_affected",
				VexJustification: "component_not_present",
			},
		},
	}
	rows := generateRows(summary)
	f, err := os.CreateTemp("", "print-vex-table")
	assert.NoError(t, err)
	defer f.Close()

	renderTable(f, getImageScanningHeadersWithVEX(true), getImageScanningColumnsAlignmentsWithVEX(true), rows)
	f.Seek(0, 0)
	got, err := io.ReadAll(f)
	assert.NoError(t, err)

	assert.Contains(t, string(got), "VEX Status")
	assert.Contains(t, string(got), "VEX Justification")
	assert.Contains(t, string(got), "not_affected")
	assert.Contains(t, string(got), "component_not_present")
}

func TestGetImageScanningHeadersWithVEX(t *testing.T) {
	headers := getImageScanningHeadersWithVEX(true)
	expectedHeaders := []string{"Severity", "Vulnerability", "Component", "Version", "Fixed in", "Image", "VEX Status", "VEX Justification"}

	for i := range headers {
		if headers[i] != expectedHeaders[i] {
			t.Errorf("expected %s, got %s", expectedHeaders[i], headers[i])
		}
	}
}

func TestGetImageScanningColumnsAlignmentsWithVEX(t *testing.T) {
	assert.Len(t, getImageScanningColumnsAlignmentsWithVEX(false), 6)
	assert.Len(t, getImageScanningColumnsAlignmentsWithVEX(true), 8)
}

func TestSummaryHasVEX(t *testing.T) {
	assert.False(t, summaryHasVEX(ImageScanSummary{}))
	assert.False(t, summaryHasVEX(ImageScanSummary{CVEs: []CVE{{ID: "CVE-1"}}}))
	assert.True(t, summaryHasVEX(ImageScanSummary{CVEs: []CVE{{ID: "CVE-1", VexStatus: "fixed"}}}))
	assert.True(t, summaryHasVEX(ImageScanSummary{CVEs: []CVE{{ID: "CVE-1", VexJustification: "component_not_present"}}}))
}

func rowToStrings(row []interface{}) []string {
	out := make([]string, 0, len(row))
	for _, cell := range row {
		if s, ok := cell.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
