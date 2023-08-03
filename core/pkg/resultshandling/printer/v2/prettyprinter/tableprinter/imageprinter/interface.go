package imageprinter

import "io"

type TablePrinter interface {
	PrintImageScanningTable(io.Writer, ImageScanSummary)
}
