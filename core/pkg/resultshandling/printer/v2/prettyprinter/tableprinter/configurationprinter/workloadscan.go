package configurationprinter

import (
	"io"

	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

type WorkloadPrinter struct {
}

var _ TablePrinter = &WorkloadPrinter{}

func NewWorkloadPrinter() *WorkloadPrinter {
	return &WorkloadPrinter{}
}

func (wp *WorkloadPrinter) PrintSummaryTable(writer io.Writer, summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {

}

func (wp *WorkloadPrinter) PrintCategoriesTables(writer io.Writer, summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {

	categoriesToCategoryControls := mapCategoryToSummary(summaryDetails.ListControls(), mapWorkloadControlsToCategories)

	for _, id := range workloadCategoriesDisplayOrder {
		categoryControl, ok := categoriesToCategoryControls[id]
		if !ok {
			continue
		}

		wp.renderSingleCategoryTable(categoryControl.CategoryName, mapCategoryToType[id], writer, categoryControl.controlSummaries, utils.MapInfoToPrintInfoFromIface(categoryControl.controlSummaries))
	}
}

func (wp *WorkloadPrinter) renderSingleCategoryTable(categoryName string, categoryType CategoryType, writer io.Writer, controlSummaries []reportsummary.IControlSummary, infoToPrintInfo []utils.InfoStars) {
	sortControlSummaries(controlSummaries)

	headers, columnAligments := wp.initCategoryTableData()

	table := getCategoryTableWriter(writer, headers, columnAligments)

	var rows [][]string
	for _, ctrls := range controlSummaries {
		var row []string
		row = generateCategoryStatusRow(ctrls, infoToPrintInfo)
		if len(row) > 0 {
			rows = append(rows, row)
		}
	}

	if len(rows) == 0 {
		return
	}

	renderSingleCategory(writer, categoryName, table, rows, infoToPrintInfo)
}

func (wp *WorkloadPrinter) initCategoryTableData() ([]string, []int) {
	return getCategoryStatusTypeHeaders(), getStatusTypeAlignments()
}

func (wp *WorkloadPrinter) generateCountingCategoryRow(controlSummary reportsummary.IControlSummary, infoToPrintInfo []utils.InfoStars) []string {

	row := make([]string, 3)

	row[0] = controlSummary.GetName()

	row[1] = getStatus(controlSummary.GetStatus(), controlSummary, infoToPrintInfo)

	row[2] = getDocsForControl(controlSummary)

	return row
}
