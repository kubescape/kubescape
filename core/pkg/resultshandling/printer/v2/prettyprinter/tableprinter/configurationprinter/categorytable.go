package configurationprinter

import (
	"io"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/olekukonko/tablewriter"
)

const (
	docsPrefix        = "https://hub.armosec.io/docs"
	scanControlPrefix = "$ kubescape scan control"
	controlNameHeader = "CONTROL NAME"
	statusHeader      = ""
	docsHeader        = "DOCS"
	resourcesHeader   = "RESOURCES"
	runHeader         = "VIEW DETAILS"
)

// initializes the table headers and column alignments based on the category type
func initCategoryTableData(categoryType CategoryType) ([]string, []int) {
	if categoryType == TypeCounting {
		return getCategoryCountingTypeHeaders(), getCountingTypeAlignments()
	}
	return getCategoryStatusTypeHeaders(), getStatusTypeAlignments()
}

func getCategoryStatusTypeHeaders() []string {
	headers := make([]string, 3)
	headers[0] = statusHeader
	headers[1] = controlNameHeader
	headers[2] = docsHeader

	return headers
}

func getCategoryCountingTypeHeaders() []string {
	headers := make([]string, 3)
	headers[0] = controlNameHeader
	headers[1] = resourcesHeader
	headers[2] = runHeader

	return headers
}

func getStatusTypeAlignments() []int {
	return []int{tablewriter.ALIGN_CENTER, tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER}
}

func getCountingTypeAlignments() []int {
	return []int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_LEFT}
}

// returns a row for status type table based on the control summary
func generateCategoryStatusRow(controlSummary reportsummary.IControlSummary, infoToPrintInfo []utils.InfoStars) []string {

	// show only passed, failed and action required controls
	status := controlSummary.GetStatus()
	if !status.IsFailed() && !status.IsSkipped() && !status.IsPassed() {
		return nil
	}

	rows := make([]string, 3)

	rows[0] = utils.GetStatusIcon(controlSummary.GetStatus().Status())

	rows[1] = controlSummary.GetName()
	if len(controlSummary.GetName()) > 50 {
		rows[1] = controlSummary.GetName()[:50] + "..."
	} else {
		rows[1] = controlSummary.GetName()
	}

	rows[2] = getDocsForControl(controlSummary)

	return rows

}

func getCategoryTableWriter(writer io.Writer, headers []string, columnAligments []int) *tablewriter.Table {
	table := tablewriter.NewWriter(writer)
	table.SetHeader(headers)
	table.SetHeaderLine(true)
	table.SetColumnAlignment(columnAligments)
	table.SetAutoWrapText(false)
	table.SetUnicodeHV(tablewriter.Regular, tablewriter.Regular)
	var headerColors []tablewriter.Colors
	for range headers {
		headerColors = append(headerColors, tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiYellowColor})
	}
	table.SetHeaderColor(headerColors...)
	return table
}

func renderSingleCategory(writer io.Writer, categoryName string, table *tablewriter.Table, rows [][]string, infoToPrintInfo []utils.InfoStars) {
	cautils.InfoTextDisplay(writer, categoryName+"\n")

	table.ClearRows()
	table.AppendBulk(rows)

	table.Render()

	if len(infoToPrintInfo) > 0 {
		printCategoryInfo(writer, infoToPrintInfo)
	}

	cautils.SimpleDisplay(writer, "\n")
}
