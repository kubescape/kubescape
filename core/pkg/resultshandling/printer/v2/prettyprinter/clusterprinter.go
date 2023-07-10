package prettyprinter

import (
	"fmt"
	"os"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

type ClusterPrinter struct {
	writer *os.File
}

func NewClusterPrinter(writer *os.File) *ClusterPrinter {
	return &ClusterPrinter{
		writer: writer,
	}
}

var _ MainPrinter = &ClusterPrinter{}

func (cp *ClusterPrinter) Print(summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {

	cp.printCategories(summaryDetails, sortedControlIDs)

	printComplianceScore(cp.writer, filterComplianceFrameworks(summaryDetails.ListFrameworks()))

	cp.printTopWorkloads(summaryDetails)

	printNextSteps(cp.writer, cp.getNextSteps())
}

func (cp *ClusterPrinter) printCategories(summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {
	categoriesTable := getCategoriesTable(cp.writer, cp.getCategoriesTableHeaders(), cp.getCategoriesColumnsAlignments())

	categoriesToControlSummariesMap := mapCategoryToControlSummaries(*summaryDetails, sortedControlIDs)

	for category, ctrls := range categoriesToControlSummariesMap {
		rows := make([][]string, 0, len(ctrls))
		for i := range ctrls {
			row := cp.generateCategoriesRow(ctrls[i])
			if len(row) > 0 {
				rows = append(rows, row)
			}
		}
		renderCategoryTable(cp.writer, categoriesTable, rows, category)
	}

}

func (cp *ClusterPrinter) getCategoriesTableHeaders() []string {
	return getCommonCategoriesTableHeaders()
}

func (cp *ClusterPrinter) getCategoriesColumnsAlignments() []int {
	return getCommonColumnsAlignments()
}

func (cp *ClusterPrinter) printTopWorkloads(summaryDetails *reportsummary.SummaryDetails) {
	cautils.InfoTextDisplay(cp.writer, getTopWorkloadsTitle(len(summaryDetails.TopWorkloadsByScore)))

	for i, wl := range summaryDetails.TopWorkloadsByScore {
		ns := wl.Workload.GetNamespace()
		name := wl.Workload.GetName()
		kind := wl.Workload.GetKind()
		cautils.SimpleDisplay(cp.writer, fmt.Sprintf("%d. namespace: %s, name: %s, kind: %s - '%s'\n", i+1, ns, name, kind, cp.getWorkloadScanCommand(ns, kind, name)))
	}

	cautils.InfoTextDisplay(cp.writer, "\n")
}

func (cp *ClusterPrinter) getWorkloadScanCommand(namespace, kind, name string) string {
	return fmt.Sprintf("$ kubescape scan workload %s/%s/%s", namespace, kind, name)
}

func (cp *ClusterPrinter) getNextSteps() []string {
	return []string{
		"compliance scan run: '$ kubescape scan framework nsa,mitre'",
		"install helm to continuing monitoring: <docs to helm>",
	}
}

func (cp *ClusterPrinter) generateCategoriesRow(controlSummary reportsummary.IControlSummary) []string {
	row := make([]string, 4)

	row[categoriesColumnSeverity] = getSeverityColumn(controlSummary)

	if len(controlSummary.GetName()) > 50 {
		row[categoriesColumnName] = controlSummary.GetName()[:50] + "..."
	} else {
		row[categoriesColumnName] = controlSummary.GetName()
	}

	setCategoryStatusRow(controlSummary, row)

	row[categoriesColumnNextSteps] = cp.generateNextSteps(controlSummary)

	return row
}

func (cp *ClusterPrinter) generateNextSteps(controlSummary reportsummary.IControlSummary) string {
	return fmt.Sprintf("$ kubescape scan control %s", controlSummary.GetID())
}
