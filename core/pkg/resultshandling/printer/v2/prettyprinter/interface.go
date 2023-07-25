package prettyprinter

import (
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

type MainPrinter interface {
	PrintConfigurationsScanning(summaryDetails *reportsummary.SummaryDetails, sortedControls [][]string)
	PrintImageScanning(imageScanSummary *imageprinter.ImageScanSummary)
	PrintNextSteps()
}
