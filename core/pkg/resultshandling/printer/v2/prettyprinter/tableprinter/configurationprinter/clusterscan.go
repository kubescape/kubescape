package configurationprinter

import (
	"fmt"
	"io"

	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

type ClusterPrinter struct{}

func NewClusterPrinter() *ClusterPrinter {
	return &ClusterPrinter{}
}

var _ TablePrinter = &ClusterPrinter{}

func (cp *ClusterPrinter) PrintSummaryTable(writer io.Writer, summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {

}

func (cp *ClusterPrinter) PrintCategoriesTable(writer io.Writer, summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {
	headers := cp.getCategoriesTableHeaders()
	columnAligments := cp.getCategoriesColumnsAlignments()

	table := getTableWriter(writer, headers, columnAligments)

	mapCategoryToRows := cp.generateRows(summaryDetails, sortedControlIDs)

	renderCategoriesTable(mapCategoryToRows, writer, table)
}

func (cp *ClusterPrinter) generateRows(summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) map[string][][]string {
	mapCategoryToRows := make(map[string][][]string)

	categoriesToControlSummariesMap := mapCategoryToControlSummaries(*summaryDetails, sortedControlIDs)

	for category, ctrls := range categoriesToControlSummariesMap {
		for i := range ctrls {
			row := cp.generateCategoriesRow(ctrls[i])
			if len(row) > 0 {
				mapCategoryToRows[category] = append(mapCategoryToRows[category], row)
			}
		}
	}

	return mapCategoryToRows
}

func (cp *ClusterPrinter) generateCategoriesRow(controlSummary reportsummary.IControlSummary) []string {
	row := make([]string, 4)

	row[categoriesColumnSeverity] = GetSeverityColumn(controlSummary)

	if len(controlSummary.GetName()) > 50 {
		row[categoriesColumnName] = controlSummary.GetName()[:50] + "..."
	} else {
		row[categoriesColumnName] = controlSummary.GetName()
	}

	setCategoryStatusRow(controlSummary, row)

	row[categoriesColumnNextSteps] = cp.generateNextSteps(controlSummary)

	return row
}

func (cp *ClusterPrinter) getCategoriesTableHeaders() []string {
	return getCommonCategoriesTableHeaders()
}

func (cp *ClusterPrinter) getCategoriesColumnsAlignments() []int {
	return getCommonColumnsAlignments()
}

func (cp *ClusterPrinter) generateNextSteps(controlSummary reportsummary.IControlSummary) string {
	return fmt.Sprintf("$ kubescape scan control %s", controlSummary.GetID())
}
