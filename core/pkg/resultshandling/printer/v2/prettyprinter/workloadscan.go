package prettyprinter

import (
	"os"

	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/configurationprinter"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

type WorkloadPrinter struct {
	writer                 *os.File
	categoriesTablePrinter configurationprinter.TablePrinter
}

func NewWorkloadPrinter(writer *os.File) *WorkloadPrinter {
	return &WorkloadPrinter{
		writer:                 writer,
		categoriesTablePrinter: configurationprinter.NewWorkloadPrinter(),
	}
}

var _ MainPrinter = &WorkloadPrinter{}

func (wp *WorkloadPrinter) PrintImageScanning(*imageprinter.ImageScanSummary) {
}

func (wp *WorkloadPrinter) PrintNextSteps() {}

func (wp *WorkloadPrinter) PrintConfigurationsScanning(summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {
	wp.categoriesTablePrinter.PrintCategoriesTable(wp.writer, summaryDetails, sortedControlIDs)

}
