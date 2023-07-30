package configurationprinter

import (
	"fmt"
	"io"

	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/olekukonko/tablewriter"
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

		infoToPrintInfo := utils.MapInfoToPrintInfoFromIface(categoryControl.controlSummaries)

		wp.renderSingleCategoryTable(categoryControl.CategoryName, mapCategoryToType[id], writer, categoryControl.controlSummaries, infoToPrintInfo)
	}
}

func (wp *WorkloadPrinter) renderSingleCategoryTable(categoryName string, categoryType CategoryType, writer io.Writer, controlSummaries []reportsummary.IControlSummary, infoToPrintInfo []utils.InfoStars) {
	headers, columnAligments := wp.initCategoryTableData(categoryType)

	table := getCategoryTableWriter(writer, headers, columnAligments)

	var rows [][]string
	for _, ctrls := range controlSummaries {
		var row []string
		if categoryType == TypeCounting {
			row = wp.generateCountingCategoryRow(ctrls)
		} else {
			row = generateCategoryStatusRow(ctrls, infoToPrintInfo)
		}
		if len(row) > 0 {
			rows = append(rows, row)
		}
	}

	if len(rows) == 0 {
		return
	}

	renderSingleCategory(writer, categoryName, table, rows, infoToPrintInfo)
}

func (wp *WorkloadPrinter) initCategoryTableData(categoryType CategoryType) ([]string, []int) {
	if categoryType == TypeCounting {
		return wp.getCategoryCountingTypeHeaders(), wp.getCountingTypeAlignments()
	}
	return getCategoryStatusTypeHeaders(), getStatusTypeAlignments()
}

func (wp *WorkloadPrinter) generateCountingCategoryRow(controlSummary reportsummary.IControlSummary) []string {

	row := make([]string, 2)

	row[0] = controlSummary.GetName()

	row[1] = fmt.Sprintf("%d", controlSummary.NumberOfResources().Failed())

	return row
}

func (wp *WorkloadPrinter) getCategoriesColumnsAlignments() []int {
	return getCountingTypeAlignments()
}

func (wp *WorkloadPrinter) generateNextSteps(controlSummary reportsummary.IControlSummary) string {
	return fmt.Sprintf("$ kubescape scan wokrload <ns>/<kind>/<name> %s", controlSummary.GetID())
}

func (wp *WorkloadPrinter) getCategoryCountingTypeHeaders() []string {
	headers := make([]string, 2)
	headers[0] = controlNameHeader
	headers[1] = resourcesHeader

	return headers
}

func (wp *WorkloadPrinter) getCountingTypeAlignments() []int {
	return []int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER}
}
