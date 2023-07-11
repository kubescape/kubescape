package prettyprinter

import (
	"fmt"
	"os"

	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

type WorkloadPrinter struct {
	writer *os.File
}

func NewWorkloadPrinter(writer *os.File) *WorkloadPrinter {
	return &WorkloadPrinter{
		writer: writer,
	}
}

var _ MainPrinter = &WorkloadPrinter{}

func (wp *WorkloadPrinter) Print(summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {
	wp.printCategories(summaryDetails, sortedControlIDs)

	printNextSteps(wp.writer, wp.getNextSteps())

}

func (wp *WorkloadPrinter) printCategories(summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {
	categoriesTable := getCategoriesTable(wp.writer, wp.getCategoriesTableHeaders(), wp.getCategoriesColumnsAlignments())

	categoriesToControlSummariesMap := mapCategoryToControlSummaries(*summaryDetails, sortedControlIDs)

	for category, ctrls := range categoriesToControlSummariesMap {
		rows := make([][]string, 0, len(ctrls))
		for i := range ctrls {
			row := wp.generateCategoriesRow(ctrls[i])
			if len(row) > 0 {
				rows = append(rows, row)
			}
		}
		renderCategoryTable(wp.writer, categoriesTable, rows, category)
	}
}

func (wp *WorkloadPrinter) getCategoriesTableHeaders() []string {
	return getCommonCategoriesTableHeaders()
}

func (wp *WorkloadPrinter) getCategoriesColumnsAlignments() []int {
	return getCommonColumnsAlignments()
}

func (wp *WorkloadPrinter) generateCategoriesRow(controlSummary reportsummary.IControlSummary) []string {
	row := make([]string, 4)

	row[categoriesColumnSeverity] = getSeverityColumn(controlSummary)

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

func (wp *WorkloadPrinter) getNextSteps() []string {
	return []string{
		"run in verbose mode: '$ kubescape scan <command> --verbose'",
		"scan helm-charts or YAML files: '$ kubescape scan /path/to/chart'",
		"add kubescape to CICD: '<docs>'",
	}
}
