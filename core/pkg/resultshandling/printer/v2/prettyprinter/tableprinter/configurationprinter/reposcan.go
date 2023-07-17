package configurationprinter

import (
	"fmt"
	"io"
	"strings"

	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

type RepoPrinter struct {
	inputPatterns []string
}

func NewRepoPrinter(inputPatterns []string) *RepoPrinter {
	return &RepoPrinter{
		inputPatterns: inputPatterns,
	}
}

var _ TablePrinter = &RepoPrinter{}

func (rp *RepoPrinter) PrintSummaryTable(writer io.Writer, summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {

}

func (rp *RepoPrinter) PrintCategoriesTable(writer io.Writer, summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {
	headers := rp.getCategoriesTableHeaders()
	columnAligments := rp.getCategoriesColumnsAlignments()

	table := getTableWriter(writer, headers, columnAligments)

	mapCategoryToRows := rp.generateRows(summaryDetails, sortedControlIDs)

	renderCategoriesTable(mapCategoryToRows, writer, table)

}

func (rp *RepoPrinter) generateRows(summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) map[string][][]string {
	mapCategoryToRows := make(map[string][][]string)

	categoriesToControlSummariesMap := mapCategoryToControlSummaries(*summaryDetails, sortedControlIDs)

	for category, ctrls := range categoriesToControlSummariesMap {
		for i := range ctrls {
			row := rp.generateCategoriesRow(ctrls[i], rp.inputPatterns)
			if len(row) > 0 {
				mapCategoryToRows[category] = append(mapCategoryToRows[category], row)
			}
		}
	}

	return mapCategoryToRows
}

func (rp *RepoPrinter) generateCategoriesRow(controlSummary reportsummary.IControlSummary, inputPatterns []string) []string {
	row := make([]string, 4)
	row[categoriesColumnSeverity] = GetSeverityColumn(controlSummary)

	if len(controlSummary.GetName()) > 50 {
		row[categoriesColumnName] = controlSummary.GetName()[:50] + "..."
	} else {
		row[categoriesColumnName] = controlSummary.GetName()
	}

	setCategoryStatusRow(controlSummary, row)

	row[categoriesColumnNextSteps] = rp.generateTableNextSteps(controlSummary, inputPatterns)

	return row
}

func (rp *RepoPrinter) getCategoriesTableHeaders() []string {
	return getCommonCategoriesTableHeaders()
}

func (rp *RepoPrinter) getCategoriesColumnsAlignments() []int {
	return getCommonColumnsAlignments()
}

func (rp *RepoPrinter) getWorkloadScanCommand(ns, kind, name string, source reporthandling.Source) string {
	cmd := fmt.Sprintf("$ kubescape scan workload %s/%s/%s", ns, kind, name)
	if ns == "" {
		cmd = fmt.Sprintf("$ kubescape scan workload %s/%s", kind, name)
	}
	if source.FileType == "Helm" {
		return fmt.Sprintf("%s --chart-path=%s", cmd, source.RelativePath)

	} else {
		return fmt.Sprintf("%s --file-path=%s", cmd, source.RelativePath)
	}
}

func (rp *RepoPrinter) generateTableNextSteps(controlSummary reportsummary.IControlSummary, inputPatterns []string) string {
	return fmt.Sprintf("$ kubescape scan control %s %s", controlSummary.GetID(), strings.Join(inputPatterns, ","))
}
