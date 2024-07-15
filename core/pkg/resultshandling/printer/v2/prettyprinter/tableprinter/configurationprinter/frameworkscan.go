package configurationprinter

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/jwalton/gchalk"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
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
		fmt.Fprintf(writer, "\nKubescape did not scan any resources. Make sure you are scanning valid manifests (Deployments, Pods, etc.)\n")
		return
	}

	// When scanning controls the framework list will be empty
	cautils.SimpleDisplay(writer, utils.FrameworksScoresToString(summaryDetails.ListFrameworks())+"\n")

	controlCountersTable := tablewriter.NewWriter(writer)

	controlCountersTable.SetColumnAlignment([]int{tablewriter.ALIGN_RIGHT, tablewriter.ALIGN_LEFT})
	controlCountersTable.SetUnicodeHVC(tablewriter.Regular, tablewriter.Regular, gchalk.Ansi256(238))
	controlCountersTable.AppendBulk(ControlCountersForSummary(summaryDetails.NumberOfControls()))
	controlCountersTable.Render()

	cautils.SimpleDisplay(writer, "\nFailed resources by severity:\n\n")

	severityCountersTable := tablewriter.NewWriter(writer)
	severityCountersTable.SetColumnAlignment([]int{tablewriter.ALIGN_RIGHT, tablewriter.ALIGN_LEFT})
	severityCountersTable.SetUnicodeHVC(tablewriter.Regular, tablewriter.Regular, gchalk.Ansi256(238))
	severityCountersTable.AppendBulk(renderSeverityCountersSummary(summaryDetails.GetResourcesSeverityCounters()))
	severityCountersTable.Render()

	cautils.SimpleDisplay(writer, "\n")

	if !fp.getVerboseMode() {
		cautils.SimpleDisplay(writer, "Run with '--verbose'/'-v' to see control failures for each resource.\n\n")
	}

	summaryTable := tablewriter.NewWriter(writer)

	summaryTable.SetAutoWrapText(false)
	summaryTable.SetHeaderLine(true)
	summaryTable.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	summaryTable.SetAutoFormatHeaders(false)
	summaryTable.SetColumnAlignment(GetColumnsAlignments())
	summaryTable.SetUnicodeHVC(tablewriter.Regular, tablewriter.Regular, gchalk.Ansi256(238))

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

	utils.PrintInfo(writer, infoToPrintInfo)
}

func shortFormatRow(dataRows [][]string) [][]string {
	rows := [][]string{}
	for _, dataRow := range dataRows {
		// Define the row content using a formatted string
		rowContent := fmt.Sprintf("Severity%s: %+v\nControl Name%s: %+v\nFailed Resources%s: %+v\nAll Resources%s: %+v\n%% Compliance-Score%s: %+v",
			strings.Repeat(" ", 11),
			dataRow[summaryColumnSeverity],
			strings.Repeat(" ", 7),
			dataRow[summaryColumnName],
			strings.Repeat(" ", 3),
			dataRow[summaryColumnCounterFailed],
			strings.Repeat(" ", 6),
			dataRow[summaryColumnCounterAll],
			strings.Repeat(" ", 1),
			dataRow[summaryColumnComplianceScore])

		// Append the formatted row content to the rows slice
		rows = append(rows, []string{rowContent})
	}
	return rows
}

func (fp *FrameworkPrinter) PrintCategoriesTables(writer io.Writer, summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {

}

func renderSeverityCountersSummary(counters reportsummary.ISeverityCounters) [][]string {

	rows := [][]string{}
	rows = append(rows, []string{"Critical", utils.GetColorForVulnerabilitySeverity("Critical")(strconv.Itoa(counters.NumberOfCriticalSeverity()))})
	rows = append(rows, []string{"High", utils.GetColorForVulnerabilitySeverity("High")(strconv.Itoa(counters.NumberOfHighSeverity()))})
	rows = append(rows, []string{"Medium", utils.GetColorForVulnerabilitySeverity("Medium")(strconv.Itoa(counters.NumberOfMediumSeverity()))})
	rows = append(rows, []string{"Low", utils.GetColorForVulnerabilitySeverity("Low")(strconv.Itoa(counters.NumberOfLowSeverity()))})

	return rows
}
