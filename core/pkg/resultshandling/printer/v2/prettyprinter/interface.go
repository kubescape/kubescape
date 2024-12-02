package prettyprinter

import (
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

type MainPrinter interface {
	PrintConfigurationsScanning(summaryDetails *reportsummary.SummaryDetails, sortedControls [][]string, topWorkloadsByScore []reporthandling.IResource)
	PrintImageScanning(imageScanSummary *imageprinter.ImageScanSummary)
	PrintNextSteps()
}
