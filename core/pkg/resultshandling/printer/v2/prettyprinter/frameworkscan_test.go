package prettyprinter

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSummaryPrinter(t *testing.T) {
	// Test case 1: Valid writer and verbose mode
	verbose := true
	printer := NewSummaryPrinter(os.Stdout, verbose)
	assert.NotNil(t, printer)
	assert.Equal(t, os.Stdout, printer.writer)
	assert.Equal(t, verbose, printer.verboseMode)
	assert.NotNil(t, printer.summaryTablePrinter)

	// Test case 2: Valid writer and non-verbose mode
	verbose = false
	printer = NewSummaryPrinter(os.Stdout, verbose)
	assert.NotNil(t, printer)
	assert.Equal(t, os.Stdout, printer.writer)
	assert.Equal(t, verbose, printer.verboseMode)
	assert.NotNil(t, printer.summaryTablePrinter)

	// Test case 3: Nil writer and verbose mode
	var writer *os.File
	verbose = true
	printer = NewSummaryPrinter(writer, verbose)
	assert.NotNil(t, printer)
	assert.Nil(t, printer.writer)
	assert.Equal(t, verbose, printer.verboseMode)
	assert.NotNil(t, printer.summaryTablePrinter)

	// Test case 4: Nil writer and non-verbose mode
	verbose = false
	printer = NewSummaryPrinter(writer, verbose)
	assert.NotNil(t, printer)
	assert.Nil(t, printer.writer)
	assert.Equal(t, verbose, printer.verboseMode)
	assert.NotNil(t, printer.summaryTablePrinter)
}

func TestGetVerboseMode(t *testing.T) {
	tests := []struct {
		name    string
		printer *SummaryPrinter
		want    bool
	}{
		{
			name: "Verbose mode on",
			printer: &SummaryPrinter{
				writer:      os.Stdout,
				verboseMode: true,
			},
			want: true,
		},
		{
			name: "Verbose mode off",
			printer: &SummaryPrinter{
				writer:      os.Stdout,
				verboseMode: false,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.printer.getVerboseMode())
		})
	}
}
