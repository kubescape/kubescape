package configurationprinter

import (
	"fmt"
	"io"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/olekukonko/tablewriter"
)

type FrameworkPrinter struct {
	verboseMode bool
}

func NewFrameworkPrinter(verboseMode bool) *FrameworkPrinter {
	return &FrameworkPrinter{
		verboseMode: verboseMode,
	}
}

var _ TablePrinter = &FrameworkPrinter{}

func (fp *FrameworkPrinter) getVerboseMode() bool {
	return fp.verboseMode
}

func (fp *FrameworkPrinter) PrintSummaryTable(writer io.Writer, summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {
	if summaryDetails.NumberOfControls().All() == 0 {
		fmt.Fprintf(writer, "\nKubescape did not scan any of the resources, make sure you are scanning valid kubernetes manifests (Deployments, Pods, etc.)\n")
		return
	}
	cautils.InfoTextDisplay(writer, "\n"+ControlCountersForSummary(summaryDetails.NumberOfControls())+"\n")
	cautils.InfoTextDisplay(writer, renderSeverityCountersSummary(summaryDetails.GetResourcesSeverityCounters())+"\n\n")

	summaryTable := tablewriter.NewWriter(writer)
	summaryTable.SetAutoWrapText(false)
	summaryTable.SetHeader(GetControlTableHeaders())
	summaryTable.SetHeaderLine(true)
	summaryTable.SetColumnAlignment(GetColumnsAlignments())

	printAll := fp.getVerboseMode()
	if summaryDetails.NumberOfResources().Failed() == 0 {
		// if there are no failed controls, print the resource table and detailed information
		printAll = true
	}

	infoToPrintInfo := utils.MapInfoToPrintInfo(summaryDetails.Controls)
	for i := len(sortedControlIDs) - 1; i >= 0; i-- {
		for _, c := range sortedControlIDs[i] {
			row := GenerateRow(summaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, c), infoToPrintInfo, printAll)
			if len(row) > 0 {
				summaryTable.Append(row)
			}
		}
	}

	summaryTable.SetFooter(GenerateFooter(summaryDetails))

	summaryTable.Render()

	// When scanning controls the framework list will be empty
	cautils.InfoTextDisplay(writer, utils.FrameworksScoresToString(summaryDetails.ListFrameworks()))

	utils.PrintInfo(writer, infoToPrintInfo)
}

func (fp *FrameworkPrinter) PrintCategoriesTable(writer io.Writer, summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {

}

func renderSeverityCountersSummary(counters reportsummary.ISeverityCounters) string {
	critical := counters.NumberOfCriticalSeverity()
	high := counters.NumberOfHighSeverity()
	medium := counters.NumberOfMediumSeverity()
	low := counters.NumberOfLowSeverity()

	return fmt.Sprintf(
		"Failed Resources by Severity: Critical — %d, High — %d, Medium — %d, Low — %d",
		critical, high, medium, low,
	)
}
