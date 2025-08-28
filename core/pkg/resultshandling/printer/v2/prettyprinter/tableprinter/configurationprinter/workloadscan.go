package configurationprinter

import (
	"io"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

type WorkloadPrinter struct {
}

var _ TablePrinter = &WorkloadPrinter{}

func NewWorkloadPrinter() *WorkloadPrinter {
	return &WorkloadPrinter{}
}

func (wp *WorkloadPrinter) PrintSummaryTable(_ io.Writer, _ *reportsummary.SummaryDetails, _ [][]string) {

}

func (wp *WorkloadPrinter) PrintCategoriesTables(writer io.Writer, summaryDetails *reportsummary.SummaryDetails, _ [][]string) {

	categoriesToCategoryControls := mapCategoryToSummary(summaryDetails.ListControls(), mapWorkloadControlsToCategories)

	for _, id := range workloadCategoriesDisplayOrder {
		categoryControl, ok := categoriesToCategoryControls[id]
		if !ok {
			continue
		}

		wp.renderSingleCategoryTable(categoryControl.CategoryName, writer, categoryControl.controlSummaries, utils.MapInfoToPrintInfoFromIface(categoryControl.controlSummaries))
	}
}

func (wp *WorkloadPrinter) renderSingleCategoryTable(categoryName string, writer io.Writer, controlSummaries []reportsummary.IControlSummary, infoToPrintInfo []utils.InfoStars) {
	sortControlSummaries(controlSummaries)

	headers, columnAlignments := wp.initCategoryTableData()

	tableWriter := getCategoryTableWriter(writer, headers, columnAlignments)

	var rows []table.Row
	for _, ctrls := range controlSummaries {
		row := generateCategoryStatusRow(ctrls)
		if len(row) > 0 {
			rows = append(rows, row)
		}
	}

	if len(rows) == 0 {
		return
	}

	renderSingleCategory(writer, categoryName, tableWriter, rows, infoToPrintInfo)
}

func (wp *WorkloadPrinter) initCategoryTableData() (table.Row, []table.ColumnConfig) {
	return getCategoryStatusTypeHeaders(), getStatusTypeAlignments()
}
