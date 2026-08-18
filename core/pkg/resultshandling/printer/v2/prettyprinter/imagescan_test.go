package prettyprinter

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
)

func TestNewImagePrinter(t *testing.T) {
	// Test case 1: Valid writer and verbose mode
	verbose := true
	printer := NewImagePrinter(os.Stdout, verbose)
	assert.NotNil(t, printer)
	assert.Equal(t, os.Stdout, printer.writer)
	assert.Equal(t, verbose, printer.verboseMode)
	assert.NotNil(t, printer.imageTablePrinter)

	// Test case 2: Valid writer and non-verbose mode
	verbose = false
	printer = NewImagePrinter(os.Stdout, verbose)
	assert.NotNil(t, printer)
	assert.Equal(t, os.Stdout, printer.writer)
	assert.Equal(t, verbose, printer.verboseMode)
	assert.NotNil(t, printer.imageTablePrinter)

	// Test case 3: Nil writer and verbose mode
	var writer *os.File
	verbose = true
	printer = NewImagePrinter(writer, verbose)
	assert.NotNil(t, printer)
	assert.Nil(t, printer.writer)
	assert.Equal(t, verbose, printer.verboseMode)
	assert.NotNil(t, printer.imageTablePrinter)

	// Test case 4: Nil writer and non-verbose mode
	verbose = false
	printer = NewImagePrinter(writer, verbose)
	assert.NotNil(t, printer)
	assert.Nil(t, printer.writer)
	assert.Equal(t, verbose, printer.verboseMode)
	assert.NotNil(t, printer.imageTablePrinter)
}

func TestPrintNextSteps_ImageScan(t *testing.T) {
	tests := []struct {
		name    string
		verbose bool
		want    string
	}{
		{
			name:    "Verbose mode on",
			verbose: true,
			want:    "\nWhat now?\n─────────\n\n* Install Kubescape in your cluster for continuous monitoring and a full vulnerability report: https://kubescape.io/docs/install-operator/\n\n",
		},
		{
			name:    "Verbose mode off",
			verbose: false,
			want:    "\nWhat now?\n─────────\n\n* Run with '--verbose'/'-v' flag for detailed vulnerabilities view\n* Install Kubescape in your cluster for continuous monitoring and a full vulnerability report: https://kubescape.io/docs/install-operator/\n\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary file to capture output
			f, err := os.CreateTemp("", "print-next-steps")
			if err != nil {
				panic(err)
			}
			defer f.Close()

			ip := NewImagePrinter(f, tt.verbose)

			// Redirect stderr to the temporary file
			oldStderr := os.Stderr
			defer func() {
				os.Stderr = oldStderr
			}()
			os.Stderr = f

			// Print the score using the `Score` function
			ip.PrintNextSteps()

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

func TestPrintImageScanningSummary_DBLinePresentWhenBuilt(t *testing.T) {
	builtAt := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	summary := imageprinter.ImageScanSummary{
		CVEs:                  []imageprinter.CVE{},
		PackageScores:         map[string]*imageprinter.PackageScore{},
		MapsSeverityToSummary: map[string]*imageprinter.SeveritySummary{},
		Images:                []string{"img:1"},
		VulnDBBuilt:           &builtAt,
	}

	f, err := os.CreateTemp("", "db-line")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	printImageScanningSummary(f, summary, false)

	f.Seek(0, 0)
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	assert.Contains(t, string(got), "Vulnerability DB built: "+builtAt.UTC().Format("2006-01-02"))
}

func TestPrintImageScanningSummary_NoDBLineWhenNil(t *testing.T) {
	summary := imageprinter.ImageScanSummary{
		CVEs:                  []imageprinter.CVE{},
		PackageScores:         map[string]*imageprinter.PackageScore{},
		MapsSeverityToSummary: map[string]*imageprinter.SeveritySummary{},
		Images:                []string{"img:1"},
	}

	f, err := os.CreateTemp("", "db-line")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	printImageScanningSummary(f, summary, false)

	f.Seek(0, 0)
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	assert.False(t, strings.Contains(string(got), "Vulnerability DB built:"))
}
