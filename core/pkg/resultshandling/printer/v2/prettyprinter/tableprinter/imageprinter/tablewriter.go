package imageprinter

import (
	"io"
)

const (
	imageColumnSeverity  = iota
	imageColumnName      = iota
	imageColumnComponent = iota
	imageColumnVersion   = iota
	imageColumnFixedIn   = iota
)

type TableWriter struct {
}

func NewTableWriter() *TableWriter {
	return &TableWriter{}
}

var _ TablePrinter = &TableWriter{}

func (tw *TableWriter) PrintImageScanningTable(writer io.Writer, summary ImageScanSummary) {
	rows := generateRows(summary)
	if len(rows) == 0 {
		return
	}

	renderTable(writer, getImageScanningHeaders(), getImageScanningColumnsAlignments(), rows)
}
