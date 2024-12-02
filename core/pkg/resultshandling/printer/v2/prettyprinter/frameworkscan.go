package prettyprinter

import (
	"os"

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
}

func NewSummaryPrinter(writer *os.File, verboseMode bool) *SummaryPrinter {
	return &SummaryPrinter{
		writer:              writer,
		verboseMode:         verboseMode,
		summaryTablePrinter: configurationprinter.NewFrameworkPrinter(verboseMode),
	}
}

var _ MainPrinter = &RepoPrinter{}

func (sp *SummaryPrinter) PrintImageScanning(*imageprinter.ImageScanSummary) {}

func (sp *SummaryPrinter) PrintNextSteps() {}

func (sp *SummaryPrinter) getVerboseMode() bool {
	return sp.verboseMode
}

func (sp *SummaryPrinter) PrintConfigurationsScanning(summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string, topWorkloadsByScore []reporthandling.IResource) {
	sp.summaryTablePrinter.PrintSummaryTable(sp.writer, summaryDetails, sortedControlIDs)
}
