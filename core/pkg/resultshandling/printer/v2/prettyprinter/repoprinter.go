package prettyprinter

import (
	"fmt"
	"os"
	"strings"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/olekukonko/tablewriter"
)

type RepoPrinter struct {
	writer        *os.File
	inputPatterns []string
}

func NewRepoPrinter(writer *os.File, inputPatterns []string) *RepoPrinter {
	return &RepoPrinter{
		writer:        writer,
		inputPatterns: inputPatterns,
	}
}

var _ MainPrinter = &RepoPrinter{}

func (rp *RepoPrinter) Print(summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {
	rp.printCategories(summaryDetails, sortedControlIDs, rp.inputPatterns)

	if len(summaryDetails.TopWorkloadsByScore) > 0 {
		rp.printTopWorkloads(summaryDetails)
	}

	printNextSteps(rp.writer, rp.getNextSteps())
}

func (rp *RepoPrinter) printCategories(summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string, inputPatterns []string) {
	categoriesTable := getCategoriesTable(rp.writer, rp.getCategoriesTableHeaders(), rp.getCategoriesColumnsAlignments())

	categoriesToControlSummariesMap := mapCategoryToControlSummaries(*summaryDetails, sortedControlIDs)

	for category, ctrls := range categoriesToControlSummariesMap {
		rows := make([][]string, 0, len(ctrls))
		for i := range ctrls {
			row := rp.generateCategoriesRow(ctrls[i], inputPatterns)
			if len(row) > 0 {
				rows = append(rows, row)
			}
		}
		renderCategoryTable(rp.writer, categoriesTable, rows, category)
	}
}

func (rp *RepoPrinter) getCategoriesTableHeaders() []string {
	return getCommonCategoriesTableHeaders()
}

func (rp *RepoPrinter) getCategoriesColumnsAlignments() []int {
	return getCommonColumnsAlignments()
}

func (rp *RepoPrinter) getNextSteps() []string {
	return []string{
		clusterScanRunText,
		CICDSetupText,
		installHelmText,
	}
}

func (rp *RepoPrinter) printNextSteps() {
	printNextSteps(rp.writer, rp.getNextSteps())
}

func (rp *RepoPrinter) printTopWorkloads(summaryDetails *reportsummary.SummaryDetails) {
	cautils.InfoTextDisplay(rp.writer, getTopWorkloadsTitle(len(summaryDetails.TopWorkloadsByScore)))

	for i, wl := range summaryDetails.TopWorkloadsByScore {
		ns := wl.Workload.GetNamespace()
		name := wl.Workload.GetName()
		kind := wl.Workload.GetKind()
		cmdPrefix := getWorkloadPrefixForCmd(ns, kind, name)
		cautils.SimpleDisplay(rp.writer, fmt.Sprintf("%d. %s - '%s'\n", i+1, cmdPrefix, rp.getWorkloadScanCommand(ns, kind, name, wl.ResourceSource)))
	}

	cautils.InfoTextDisplay(rp.writer, "\n")
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

func (rp *RepoPrinter) renderSingleCategory(category string, ctrls []reportsummary.IControlSummary, categoriesTable *tablewriter.Table) {
	cautils.InfoTextDisplay(rp.writer, "\n"+category+"\n")

	categoriesTable.ClearRows()
	for i := range ctrls {
		row := rp.generateCategoriesRow(ctrls[i], rp.inputPatterns)
		if len(row) > 0 {
			categoriesTable.Append(row)
		}
	}
	categoriesTable.Render()
}

func (rp *RepoPrinter) generateCategoriesRow(controlSummary reportsummary.IControlSummary, inputPatterns []string) []string {
	row := make([]string, 4)
	row[categoriesColumnSeverity] = getSeverityColumn(controlSummary)

	if len(controlSummary.GetName()) > 50 {
		row[categoriesColumnName] = controlSummary.GetName()[:50] + "..."
	} else {
		row[categoriesColumnName] = controlSummary.GetName()
	}

	setCategoryStatusRow(controlSummary, row)

	row[categoriesColumnNextSteps] = rp.generateTableNextSteps(controlSummary, inputPatterns)

	return row
}

func (rp *RepoPrinter) generateTableNextSteps(controlSummary reportsummary.IControlSummary, inputPatterns []string) string {
	return fmt.Sprintf("$ kubescape scan control %s %s", controlSummary.GetID(), strings.Join(inputPatterns, ","))
}
