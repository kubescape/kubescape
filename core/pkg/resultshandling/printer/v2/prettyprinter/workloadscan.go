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

func (wp *WorkloadPrinter) PrintImageScanning(summary *imageprinter.ImageScanSummary) {
	printImageScanningSummary(wp.writer, *summary, false)
	printImagesCommands(wp.writer, *summary)
}

func (wp *WorkloadPrinter) PrintNextSteps() {
	printNextSteps(wp.writer, wp.getNextSteps())
}

func (wp *WorkloadPrinter) getNextSteps() []string {
	return []string{
		configScanVerboseRunText,
		installHelmText,
		CICDSetupText,
	}
}

func (wp *WorkloadPrinter) PrintConfigurationsScanning(summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {
	wp.categoriesTablePrinter.PrintCategoriesTables(wp.writer, summaryDetails, sortedControlIDs)

}
