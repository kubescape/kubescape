package prettyprinter

import (
	"os"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/configurationprinter"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

var _ MainPrinter = &SummaryPrinter{}

type SummaryPrinter struct {
	writer              *os.File
	verboseMode         bool
	summaryTablePrinter configurationprinter.TablePrinter
	imageTablePrinter   imageprinter.TablePrinter
}

func NewSummaryPrinter(writer *os.File, verboseMode bool) *SummaryPrinter {
	return &SummaryPrinter{
		writer:              writer,
		verboseMode:         verboseMode,
		summaryTablePrinter: configurationprinter.NewFrameworkPrinter(verboseMode),
		imageTablePrinter:   imageprinter.NewTableWriter(),
	}
}

func (sp *SummaryPrinter) PrintImageScanning(summary *imageprinter.ImageScanSummary) {
	if sp.verboseMode {
		sp.imageTablePrinter.PrintImageScanningTable(sp.writer, *summary)
		cautils.SimpleDisplay(sp.writer, "\n")
	}
	printImageScanningSummary(sp.writer, *summary, sp.verboseMode)
	if !sp.verboseMode {
		printImagesCommands(sp.writer, *summary)
	}
	printTopComponents(sp.writer, *summary)
}

func (sp *SummaryPrinter) PrintNextSteps() {}

func (sp *SummaryPrinter) getVerboseMode() bool {
	return sp.verboseMode
}

func (sp *SummaryPrinter) PrintConfigurationsScanning(summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string, topWorkloadsByScore []reporthandling.IResource) {
	sp.summaryTablePrinter.PrintSummaryTable(sp.writer, summaryDetails, sortedControlIDs)
}
