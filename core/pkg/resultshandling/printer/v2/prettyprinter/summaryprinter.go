package prettyprinter

import (
	"fmt"
	"os"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/olekukonko/tablewriter"
)

const (
	summaryColumnSeverity        = iota
	summaryColumnName            = iota
	summaryColumnCounterFailed   = iota
	summaryColumnCounterAll      = iota
	summaryColumnComplianceScore = iota
	_summaryRowLen               = iota
)

var _ MainPrinter = &SummaryPrinter{}

type SummaryPrinter struct {
	writer      *os.File
	verboseMode bool
}

func NewSummaryPrinter(writer *os.File, verboseMode bool) *SummaryPrinter {
	return &SummaryPrinter{
		writer:      writer,
		verboseMode: verboseMode,
	}
}

var _ MainPrinter = &RepoPrinter{}

func (sp *SummaryPrinter) getVerboseMode() bool {
	return sp.verboseMode
}

func (sp *SummaryPrinter) Print(summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {
	sp.printSummary(sp.writer, summaryDetails, sortedControlIDs)
}

func (sp *SummaryPrinter) printSummary(writer *os.File, summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {
	if summaryDetails.NumberOfControls().All() == 0 {
		fmt.Fprintf(writer, "\nKubescape did not scan any of the resources, make sure you are scanning valid kubernetes manifests (Deployments, Pods, etc.)\n")
		return
	}
	cautils.InfoTextDisplay(writer, "\n"+ControlCountersForSummary(summaryDetails.NumberOfControls())+"\n")
	cautils.InfoTextDisplay(writer, renderSeverityCountersSummary(summaryDetails.GetResourcesSeverityCounters())+"\n\n")

	summaryTable := tablewriter.NewWriter(writer)
	summaryTable.SetAutoWrapText(false)
	summaryTable.SetHeader(getControlTableHeaders())
	summaryTable.SetHeaderLine(true)
	summaryTable.SetColumnAlignment(getColumnsAlignments())

	printAll := sp.getVerboseMode()
	if summaryDetails.NumberOfResources().Failed() == 0 {
		// if there are no failed controls, print the resource table and detailed information
		printAll = true
	}

	infoToPrintInfo := mapInfoToPrintInfo(summaryDetails.Controls)
	for i := len(sortedControlIDs) - 1; i >= 0; i-- {
		for _, c := range sortedControlIDs[i] {
			row := generateRow(summaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, c), infoToPrintInfo, printAll)
			if len(row) > 0 {
				summaryTable.Append(row)
			}
		}
	}

	summaryTable.SetFooter(generateFooter(summaryDetails))

	summaryTable.Render()

	// When scanning controls the framework list will be empty
	cautils.InfoTextDisplay(writer, frameworksScoresToString(summaryDetails.ListFrameworks()))

	printInfo(writer, infoToPrintInfo)
}
