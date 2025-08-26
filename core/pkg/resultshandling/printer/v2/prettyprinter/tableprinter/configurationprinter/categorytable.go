package configurationprinter

import (
	"io"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
)

const (
	docsPrefix        = "https://kubescape.io/docs"
	scanControlPrefix = "$ kubescape scan control"
	controlNameHeader = "Control name"
	statusHeader      = ""
	docsHeader        = "Docs"
	resourcesHeader   = "Resources"
	runHeader         = "View details"
)

// initializes the table headers and column alignments based on the category type
func initCategoryTableData(categoryType CategoryType) []string {
	if categoryType == TypeCounting {
		return getCategoryCountingTypeHeaders()
	}
	return getCategoryStatusTypeHeaders()
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

func getCategoryTableWriter(writer io.Writer, headers []string) *tablewriter.Table {
	table := tablewriter.NewTable(writer,
		tablewriter.WithHeaderAlignment(tw.AlignLeft),
		tablewriter.WithHeaderAutoFormat(tw.Off),
		tablewriter.WithRenderer(renderer.NewBlueprint()),
		tablewriter.WithRendition(tw.Rendition{
			Borders: tw.Border{ // Outer table borders
				Left:   tw.On,
				Right:  tw.On,
				Top:    tw.On,
				Bottom: tw.On,
			},
			Settings: tw.Settings{
				Lines: tw.Lines{ // Major internal separator lines
					ShowHeaderLine: tw.On, // Line after header
					ShowFooterLine: tw.On, // Line before footer (if footer exists)
				},
				Separators: tw.Separators{ // General row and column separators
					BetweenRows:    tw.On, // Horizontal lines between data rows
					BetweenColumns: tw.On, // Vertical lines between columns
				},
			},
		}),
	)
	table.Header(headers)
	return table
}

func renderSingleCategory(writer io.Writer, categoryName string, table *tablewriter.Table, rows [][]string, infoToPrintInfo []utils.InfoStars) {

	cautils.InfoDisplay(writer, categoryName+"\n")

	table.Reset()
	table.Append(rows)

	table.Render()

	if len(infoToPrintInfo) > 0 {
		printCategoryInfo(writer, infoToPrintInfo)
	}

	cautils.SimpleDisplay(writer, "\n")
}
