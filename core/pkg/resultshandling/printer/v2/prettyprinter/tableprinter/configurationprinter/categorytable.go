package configurationprinter

import (
	"io"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

const (
	docsPrefix        = "https://kubescape.io/docs/controls"
	scanControlPrefix = "$ kubescape scan control"
	controlNameHeader = "Control name"
	statusHeader      = ""
	docsHeader        = "Docs"
	resourcesHeader   = "Resources"
	runHeader         = "View details"
)

// initializes the table headers and column alignments based on the category type
func initCategoryTableData(categoryType CategoryType) (table.Row, []table.ColumnConfig) {
	if categoryType == TypeCounting {
		return getCategoryCountingTypeHeaders(), getCountingTypeAlignments()
	}
	return getCategoryStatusTypeHeaders(), getStatusTypeAlignments()
}

func getCategoryStatusTypeHeaders() table.Row {
	headers := make(table.Row, 3)
	headers[0] = statusHeader
	headers[1] = controlNameHeader
	headers[2] = docsHeader

	return headers
}

func getCategoryCountingTypeHeaders() table.Row {
	headers := make(table.Row, 3)
	headers[0] = controlNameHeader
	headers[1] = resourcesHeader
	headers[2] = runHeader

	return headers
}

func getStatusTypeAlignments() []table.ColumnConfig {
	return []table.ColumnConfig{{Number: 1, Align: text.AlignCenter}, {Number: 2, Align: text.AlignLeft}, {Number: 3, Align: text.AlignCenter}}
}

func getCountingTypeAlignments() []table.ColumnConfig {
	return []table.ColumnConfig{{Number: 1, Align: text.AlignLeft}, {Number: 2, Align: text.AlignCenter}, {Number: 3, Align: text.AlignLeft}}
}

// returns a row for status type table based on the control summary
func generateCategoryStatusRow(controlSummary reportsummary.IControlSummary) table.Row {

	// show only passed, failed and action required controls
	status := controlSummary.GetStatus()
	if !status.IsFailed() && !status.IsSkipped() && !status.IsPassed() {
		return nil
	}

	rows := make(table.Row, 3)

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

func getCategoryTableWriter(writer io.Writer, headers table.Row, columnAlignments []table.ColumnConfig) table.Writer {
	tableWriter := table.NewWriter()
	tableWriter.SetOutputMirror(writer)
	tableWriter.AppendHeader(headers)
	tableWriter.Style().Options.SeparateHeader = true
	tableWriter.Style().Format.HeaderAlign = text.AlignLeft
	tableWriter.Style().Format.Header = text.FormatDefault
	tableWriter.SetColumnConfigs(columnAlignments)
	tableWriter.Style().Box = table.StyleBoxRounded
	return tableWriter
}

func renderSingleCategory(writer io.Writer, categoryName string, tableWriter table.Writer, rows []table.Row, infoToPrintInfo []utils.InfoStars) {

	cautils.InfoDisplay(writer, categoryName+"\n")

	tableWriter.ResetRows()
	tableWriter.AppendRows(rows)

	tableWriter.Render()

	if len(infoToPrintInfo) > 0 {
		printCategoryInfo(writer, infoToPrintInfo)
	}

	cautils.SimpleDisplay(writer, "\n")
}
