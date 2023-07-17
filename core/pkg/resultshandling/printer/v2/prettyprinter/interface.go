package prettyprinter

import (
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

type MainPrinter interface {
	PrintConfigurationsScanning(*reportsummary.SummaryDetails, [][]string)
	PrintImageScanning(*imageprinter.ImageScanSummary)
	PrintNextSteps()
}
