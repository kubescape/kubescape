package configurationprinter

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
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

	controlCountersTable := table.NewWriter()
	controlCountersTable.SetOutputMirror(writer)

	controlCountersTable.SetColumnConfigs([]table.ColumnConfig{{Number: 1, Align: text.AlignRight}, {Number: 2, Align: text.AlignLeft}})
	controlCountersTable.Style().Box = table.StyleBoxRounded
	controlCountersTable.AppendRows(ControlCountersForSummary(summaryDetails.NumberOfControls()))
	controlCountersTable.Render()

	cautils.SimpleDisplay(writer, "\nFailed resources by severity:\n\n")

	severityCountersTable := table.NewWriter()
	severityCountersTable.SetOutputMirror(writer)
	severityCountersTable.SetColumnConfigs([]table.ColumnConfig{{Number: 1, Align: text.AlignRight}, {Number: 2, Align: text.AlignLeft}})
	severityCountersTable.Style().Box = table.StyleBoxRounded
	severityCountersTable.AppendRows(renderSeverityCountersSummary(summaryDetails.GetResourcesSeverityCounters()))
	severityCountersTable.Render()

	cautils.SimpleDisplay(writer, "\n")

	if !fp.getVerboseMode() {
		cautils.SimpleDisplay(writer, "Run with '--verbose'/'-v' to see control failures for each resource.\n\n")
	}

	summaryTable := table.NewWriter()
	summaryTable.SetOutputMirror(writer)

	summaryTable.Style().Options.SeparateHeader = true
	summaryTable.Style().Format.HeaderAlign = text.AlignLeft
	summaryTable.Style().Format.Header = text.FormatDefault
	summaryTable.Style().Format.Footer = text.FormatDefault
	summaryTable.SetColumnConfigs(GetColumnsAlignments())
	summaryTable.Style().Box = table.StyleBoxRounded

	printAll := fp.getVerboseMode()
	if summaryDetails.NumberOfResources().Failed() == 0 {
		// if there are no failed controls, print the resource table and detailed information
		printAll = true
	}

	var dataRows []table.Row

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
		summaryTable.Style().Options.SeparateRows = true
		dataRows = shortFormatRow(dataRows)
	} else {
		summaryTable.SetColumnConfigs(GetColumnsAlignments())
		summaryTable.Style().Format.FooterAlign = text.AlignCenter
	}
	summaryTable.AppendHeader(GetControlTableHeaders(short))
	summaryTable.AppendFooter(GenerateFooter(summaryDetails, short))

	summaryTable.AppendRows(dataRows)
	summaryTable.Render()

	utils.PrintInfo(writer, infoToPrintInfo)
}

func shortFormatRow(dataRows []table.Row) []table.Row {
	rows := make([]table.Row, 0, len(dataRows))
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
		rows = append(rows, table.Row{rowContent})
	}
	return rows
}

func (fp *FrameworkPrinter) PrintCategoriesTables(_ io.Writer, _ *reportsummary.SummaryDetails, _ [][]string) {

}

func renderSeverityCountersSummary(counters reportsummary.ISeverityCounters) []table.Row {

	rows := make([]table.Row, 0, 4)
	rows = append(rows, table.Row{"Critical", utils.GetColorForVulnerabilitySeverity("Critical")(strconv.Itoa(counters.NumberOfCriticalSeverity()))})
	rows = append(rows, table.Row{"High", utils.GetColorForVulnerabilitySeverity("High")(strconv.Itoa(counters.NumberOfHighSeverity()))})
	rows = append(rows, table.Row{"Medium", utils.GetColorForVulnerabilitySeverity("Medium")(strconv.Itoa(counters.NumberOfMediumSeverity()))})
	rows = append(rows, table.Row{"Low", utils.GetColorForVulnerabilitySeverity("Low")(strconv.Itoa(counters.NumberOfLowSeverity()))})

	return rows
}
