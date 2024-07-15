package imageprinter

import (
	"io"
	"os"
	"testing"

	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/stretchr/testify/assert"
)

func TestPrintImageScanningTable(t *testing.T) {
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

			tw := NewTableWriter()
			tw.PrintImageScanningTable(f, tt.summary)

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

func TestNewTableWriter(t *testing.T) {
	tw := NewTableWriter()
	assert.NotNil(t, tw)
	assert.Empty(t, tw)
}
