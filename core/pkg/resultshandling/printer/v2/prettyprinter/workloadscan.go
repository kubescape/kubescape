package prettyprinter

import (
	"os"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/configurationprinter"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

type WorkloadPrinter struct {
	writer                 *os.File
	categoriesTablePrinter configurationprinter.TablePrinter
	imageTablePrinter      imageprinter.TablePrinter
	verboseMode            bool
}

func NewWorkloadPrinter(writer *os.File, verboseMode bool) *WorkloadPrinter {
	return &WorkloadPrinter{
		writer:                 writer,
		categoriesTablePrinter: configurationprinter.NewWorkloadPrinter(),
		imageTablePrinter:      imageprinter.NewTableWriter(),
		verboseMode:            verboseMode,
	}
}

var _ MainPrinter = &WorkloadPrinter{}

func (wp *WorkloadPrinter) PrintImageScanning(summary *imageprinter.ImageScanSummary) {
	if wp.verboseMode {
		wp.imageTablePrinter.PrintImageScanningTable(wp.writer, *summary)
		cautils.SimpleDisplay(wp.writer, "\n")
	}
	printImageScanningSummary(wp.writer, *summary, wp.verboseMode)
	if !wp.verboseMode {
		printImagesCommands(wp.writer, *summary)
	}
}

func (wp *WorkloadPrinter) PrintNextSteps() {
	printNextSteps(wp.writer, wp.getNextSteps(), true)
}

func (wp *WorkloadPrinter) getNextSteps() []string {
	return []string{
		runCommandsText,
		configScanVerboseRunText,
		installKubescapeText,
	}
}

func (wp *WorkloadPrinter) PrintConfigurationsScanning(summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string, topWorkloadsByScore []reporthandling.IResource) {
	wp.categoriesTablePrinter.PrintCategoriesTables(wp.writer, summaryDetails, sortedControlIDs)

}
