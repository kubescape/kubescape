package configurationprinter

import (
	"fmt"
	"io"

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

func (wp *WorkloadPrinter) PrintCategoriesTable(writer io.Writer, summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {

	headers := wp.getCategoriesTableHeaders()
	columnAligments := wp.getCategoriesColumnsAlignments()

	table := getTableWriter(writer, headers, columnAligments)

	mapCategoryToRows := wp.generateRows(summaryDetails, sortedControlIDs)

	renderCategoriesTable(mapCategoryToRows, writer, table)
}

func (wp *WorkloadPrinter) generateRows(summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) map[string][][]string {
	mapCategoryToRows := make(map[string][][]string)

	categoriesToControlSummariesMap := mapCategoryToControlSummaries(*summaryDetails, sortedControlIDs)

	for category, ctrls := range categoriesToControlSummariesMap {
		for i := range ctrls {
			row := wp.generateCategoriesRow(ctrls[i])
			if len(row) > 0 {
				mapCategoryToRows[category] = append(mapCategoryToRows[category], row)
			}
		}
	}

	return mapCategoryToRows
}

func (wp *WorkloadPrinter) getCategoriesTableHeaders() []string {
	return getCommonCategoriesTableHeaders()
}

func (wp *WorkloadPrinter) getCategoriesColumnsAlignments() []int {
	return getCommonColumnsAlignments()
}

func (wp *WorkloadPrinter) generateCategoriesRow(controlSummary reportsummary.IControlSummary) []string {
	row := make([]string, 4)

	row[categoriesColumnSeverity] = GetSeverityColumn(controlSummary)

	if len(controlSummary.GetName()) > 50 {
		row[categoriesColumnName] = controlSummary.GetName()[:50] + "..."
	} else {
		row[categoriesColumnName] = controlSummary.GetName()
	}

	setCategoryStatusRow(controlSummary, row)

	row[categoriesColumnNextSteps] = wp.generateNextSteps(controlSummary)

	return row
}

func (wp *WorkloadPrinter) generateNextSteps(controlSummary reportsummary.IControlSummary) string {
	return fmt.Sprintf("$ kubescape scan wokrload <ns>/<kind>/<name> %s", controlSummary.GetID())
}
