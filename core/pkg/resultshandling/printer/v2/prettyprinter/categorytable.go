package prettyprinter

import (
	"os"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/olekukonko/tablewriter"
)

const (
	categoriesColumnSeverity  = iota
	categoriesColumnName      = iota
	categoriesColumnFailed    = iota
	categoriesColumnNextSteps = iota
)

func renderCategoryTable(writer *os.File, table *tablewriter.Table, rows [][]string, category string) {
	cautils.InfoTextDisplay(writer, "\n"+category+"\n")

	table.ClearRows()
	table.AppendBulk(rows)

	table.Render()

	cautils.SimpleDisplay(writer, "\n")
}

func getCategoriesTable(writer *os.File, headers []string, columnAligments []int) *tablewriter.Table {
	categoriesTable := tablewriter.NewWriter(writer)
	categoriesTable.SetHeader(headers)
	categoriesTable.SetHeaderLine(true)
	categoriesTable.SetColumnAlignment(columnAligments)

	return categoriesTable
}

func setCategoryStatusRow(controlSummary reportsummary.IControlSummary, row []string) {
	status := controlSummary.GetStatus().Status()
	if status == apis.StatusSkipped {
		status = "action required"
	}
	row[categoriesColumnFailed] = string(status)
}

func getCommonCategoriesTableHeaders() []string {
	headers := make([]string, 4)
	headers[categoriesColumnSeverity] = "SEVERITY"
	headers[categoriesColumnName] = "CONTROL NAME"
	headers[categoriesColumnFailed] = "STATUS"
	headers[categoriesColumnNextSteps] = "NEXT STEP"

	return headers
}

func getCategoriesTableHeaders() []string {
	headers := make([]string, 4)
	headers[categoriesColumnSeverity] = "SEVERITY"
	headers[categoriesColumnName] = "CONTROL NAME"
	headers[categoriesColumnFailed] = "FAILED RESOURCES"
	headers[categoriesColumnNextSteps] = "NEXT STEPS"

	return headers
}

func getCategoriesColumnsAlignments() []int {
	alignments := make([]int, 4)
	alignments[categoriesColumnSeverity] = tablewriter.ALIGN_LEFT
	alignments[categoriesColumnName] = tablewriter.ALIGN_LEFT
	alignments[categoriesColumnFailed] = tablewriter.ALIGN_CENTER
	alignments[categoriesColumnNextSteps] = tablewriter.ALIGN_LEFT

	return alignments
}

func mapCategoryToControlSummaries(summaryDetails reportsummary.SummaryDetails, sortedControlIDs [][]string) map[string][]reportsummary.IControlSummary {
	categories := map[string][]reportsummary.IControlSummary{}

	for i := len(sortedControlIDs) - 1; i >= 0; i-- {
		for _, c := range sortedControlIDs[i] {
			ctrl := summaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, c)
			if ctrl.GetStatus().Status() == apis.StatusPassed {
				continue
			}
			for j := range ctrl.GetCategories() {
				categories[ctrl.GetCategories()[j]] = append(categories[ctrl.GetCategories()[j]], ctrl)
			}
		}
	}

	return categories
}
