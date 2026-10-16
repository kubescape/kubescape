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
			want: "╭──────────┬───────────────┬─────┬──────┬───────────┬─────────┬──────────┬──────────────╮\n│ Severity │ Vulnerability │ KEV │ EPSS │ Component │ Version │ Fixed in │ Image        │\n├──────────┼───────────────┼─────┼──────┼───────────┼─────────┼──────────┼──────────────┤\n│   High   │ CVE-2020-0002 │     │  N/A │ package2  │ 1.0.0   │          │ alpine:3.18  │\n│  Medium  │ CVE-2020-0003 │     │  N/A │ package3  │ 1.0.0   │          │ ubuntu:22.04 │\n│    Low   │ CVE-2020-0001 │     │  N/A │ package1  │ 1.0.0   │          │ nginx:latest │\n╰──────────┴───────────────┴─────┴──────┴───────────┴─────────┴──────────┴──────────────╯\n",
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
			want: "╭──────────┬───────────────┬─────┬──────┬───────────┬─────────┬──────────┬─────────────╮\n│ Severity │ Vulnerability │ KEV │ EPSS │ Component │ Version │ Fixed in │ Image       │\n├──────────┼───────────────┼─────┼──────┼───────────┼─────────┼──────────┼─────────────┤\n│   High   │ CVE-2020-0002 │     │  N/A │ package2  │ 1.0.0   │ v1,v2    │ golang:1.24 │\n│    Low   │ CVE-2020-0001 │     │  N/A │ package1  │ 1.0.0   │          │ test:latest │\n╰──────────┴───────────────┴─────┴──────┴───────────┴─────────┴──────────┴─────────────╯\n",
		},
		{
			name: "check KEV and EPSS are shown and drive the order",
			summary: ImageScanSummary{
				CVEs: []CVE{
					{
						ID:         "CVE-2020-0001",
						Severity:   "Critical",
						Package:    "package1",
						Version:    "1.0.0",
						FixedState: string(v5.NotFixedState),
						Image:      "nginx:1.17.0",
						EPSS:       &EPSS{Score: 0.004, Percentile: 0.61},
					},
					{
						ID:         "CVE-2020-15999",
						Severity:   "Medium",
						Package:    "libfreetype6",
						Version:    "2.9.1",
						FixedState: string(v5.NotFixedState),
						Image:      "nginx:1.17.0",
						KEV:        true,
						EPSS:       &EPSS{Score: 0.63894, Percentile: 0.99215},
					},
					{
						ID:         "CVE-2020-0002",
						Severity:   "Critical",
						Package:    "package2",
						Version:    "1.0.0",
						FixedState: string(v5.NotFixedState),
						Image:      "nginx:1.17.0",
						EPSS:       &EPSS{Score: 0.2, Percentile: 0.95},
					},
				},
			},
			want: "╭──────────┬────────────────┬─────┬──────────────┬──────────────┬─────────┬──────────┬──────────────╮\n│ Severity │ Vulnerability  │ KEV │ EPSS         │ Component    │ Version │ Fixed in │ Image        │\n├──────────┼────────────────┼─────┼──────────────┼──────────────┼─────────┼──────────┼──────────────┤\n│  Medium  │ CVE-2020-15999 │ yes │ 63.9% (99th) │ libfreetype6 │ 2.9.1   │          │ nginx:1.17.0 │\n│ Critical │ CVE-2020-0002  │     │ 20.0% (95th) │ package2     │ 1.0.0   │          │ nginx:1.17.0 │\n│ Critical │ CVE-2020-0001  │     │  0.4% (61st) │ package1     │ 1.0.0   │          │ nginx:1.17.0 │\n╰──────────┴────────────────┴─────┴──────────────┴──────────────┴─────────┴──────────┴──────────────╯\n",
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
				{"High", "CVE-2020-0002", "", "N/A", "package2", "1.0.0", "", "alpine:3.18"},
				{"Medium", "CVE-2020-0003", "", "N/A", "package3", "1.0.0", "", "ubuntu:22.04"},
				{"Low", "CVE-2020-0001", "", "N/A", "package1", "1.0.0", "", "nginx:latest"},
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
				{"High", "CVE-2020-0002", "", "N/A", "package2", "1.0.0", "v1,v2", "golang:1.24"},
				{"Low", "CVE-2020-0001", "", "N/A", "package1", "1.0.0", "", "test:latest"},
			},
		},
	}

	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			actualRows := generateRows(tt.summary)
			got := make([][]string, len(actualRows))
			for i := range actualRows {
				got[i] = rowToStrings(actualRows[i])
			}
			assert.Equal(t, tt.expectedRows, got)
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
			want: []string{"High", "CVE-2020-0001", "", "N/A", "package1", "1.0.0", "v1,v2", "golang:1.24"},
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
			want: []string{"High", "CVE-2020-0001", "", "N/A", "package1", "1.0.0", "", "nginx:latest"},
		},
		{
			name: "check row with KEV and EPSS",
			cve: CVE{
				Severity:   "Medium",
				ID:         "CVE-2020-15999",
				Package:    "libfreetype6",
				Version:    "2.9.1",
				FixedState: string(v5.NotFixedState),
				Image:      "nginx:1.17.0",
				KEV:        true,
				EPSS:       &EPSS{Score: 0.63894, Percentile: 0.99215},
			},
			want: []string{"Medium", "CVE-2020-15999", "yes", "63.9% (99th)", "libfreetype6", "2.9.1", "", "nginx:1.17.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, rowToStrings(generateRow(tt.cve)))
		})
	}
}

func TestGetImageScanningHeaders(t *testing.T) {
	headers := getImageScanningHeaders()

	expectedHeaders := []string{"Severity", "Vulnerability", "KEV", "EPSS", "Component", "Version", "Fixed in", "Image"}

	assert.Equal(t, expectedHeaders, rowToStrings(headers))
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
		"",
		"N/A",
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
		"",
		"N/A",
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
	expectedHeaders := []string{"Severity", "Vulnerability", "KEV", "EPSS", "Component", "Version", "Fixed in", "Image", "VEX Status", "VEX Justification"}

	assert.Equal(t, expectedHeaders, rowToStrings(headers))
}

func TestGetImageScanningColumnsAlignmentsWithVEX(t *testing.T) {
	assert.Len(t, getImageScanningColumnsAlignmentsWithVEX(false), 8)
	assert.Len(t, getImageScanningColumnsAlignmentsWithVEX(true), 10)
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
