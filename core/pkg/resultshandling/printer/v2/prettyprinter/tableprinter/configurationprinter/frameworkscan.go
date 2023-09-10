package configurationprinter

import (
	"fmt"
	"io"
	"strings"

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
	summaryTable.SetHeaderLine(true)
	summaryTable.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	summaryTable.SetAutoFormatHeaders(false)
	summaryTable.SetColumnAlignment(GetColumnsAlignments())
	summaryTable.SetUnicodeHV(tablewriter.Regular, tablewriter.Regular)

	printAll := fp.getVerboseMode()
	if summaryDetails.NumberOfResources().Failed() == 0 {
		// if there are no failed controls, print the resource table and detailed information
		printAll = true
	}

	dataRows := [][]string{}

	infoToPrintInfo := utils.MapInfoToPrintInfo(summaryDetails.Controls)
	for i := len(sortedControlIDs) - 1; i >= 0; i-- {
		for _, c := range sortedControlIDs[i] {
			row := GenerateRow(summaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, c), infoToPrintInfo, printAll)
			if len(row) > 0 {
				dataRows = append(dataRows, row)
			}
		}
	}

	short := utils.CheckShortTerminalWidth(dataRows, GetControlTableHeaders(false))
	if short {
		summaryTable.SetRowLine(true)
		dataRows = shortFormatRow(dataRows)
	} else {
		summaryTable.SetColumnAlignment(GetColumnsAlignments())
	}
	summaryTable.SetHeader(GetControlTableHeaders(short))
	summaryTable.SetFooter(GenerateFooter(summaryDetails, short))

	var headerColors []tablewriter.Colors
	for range dataRows[0] {
		headerColors = append(headerColors, tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiYellowColor})
	}
	summaryTable.SetHeaderColor(headerColors...)

	summaryTable.AppendBulk(dataRows)
	summaryTable.Render()

	// When scanning controls the framework list will be empty
	cautils.InfoTextDisplay(writer, utils.FrameworksScoresToString(summaryDetails.ListFrameworks()))

	utils.PrintInfo(writer, infoToPrintInfo)
}

func shortFormatRow(dataRows [][]string) [][]string {
	rows := [][]string{}
	for _, dataRow := range dataRows {
		rows = append(rows, []string{fmt.Sprintf("Severity"+strings.Repeat(" ", 11)+": %+v\nControl Name"+strings.Repeat(" ", 7)+": %+v\nFailed Resources"+strings.Repeat(" ", 3)+": %+v\nAll Resources"+strings.Repeat(" ", 6)+": %+v\n%% Compliance-Score"+strings.Repeat(" ", 1)+": %+v", dataRow[summaryColumnSeverity], dataRow[summaryColumnName], dataRow[summaryColumnCounterFailed], dataRow[summaryColumnCounterAll], dataRow[summaryColumnComplianceScore])})
	}
	return rows
}

func (fp *FrameworkPrinter) PrintCategoriesTables(writer io.Writer, summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {

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
