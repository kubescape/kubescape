package configurationprinter

import (
	"fmt"
	"io"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jwalton/gchalk"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

type ClusterPrinter struct{}

func NewClusterPrinter() *ClusterPrinter {
	return &ClusterPrinter{}
}

var _ TablePrinter = &ClusterPrinter{}

func (cp *ClusterPrinter) PrintSummaryTable(_ io.Writer, _ *reportsummary.SummaryDetails, _ [][]string) {

}

func (cp *ClusterPrinter) PrintCategoriesTables(writer io.Writer, summaryDetails *reportsummary.SummaryDetails, _ [][]string) {

	categoriesToCategoryControls := mapCategoryToSummary(summaryDetails.ListControls(), mapClusterControlsToCategories)

	for _, id := range clusterCategoriesDisplayOrder {
		categoryControl, ok := categoriesToCategoryControls[id]
		if !ok {
			continue
		}

		cp.renderSingleCategoryTable(categoryControl.CategoryName, mapCategoryToType[id], writer, categoryControl.controlSummaries, utils.MapInfoToPrintInfoFromIface(categoryControl.controlSummaries))
	}
}

func (cp *ClusterPrinter) renderSingleCategoryTable(categoryName string, categoryType CategoryType, writer io.Writer, controlSummaries []reportsummary.IControlSummary, infoToPrintInfo []utils.InfoStars) {
	sortControlSummaries(controlSummaries)

	headers, columnAlignments := initCategoryTableData(categoryType)

	tableWriter := getCategoryTableWriter(writer, headers, columnAlignments)

	var rows []table.Row
	for _, ctrls := range controlSummaries {
		var row table.Row
		if categoryType == TypeCounting {
			row = cp.generateCountingCategoryRow(ctrls)
		} else {
			row = generateCategoryStatusRow(ctrls)
		}
		if len(row) > 0 {
			rows = append(rows, row)
		}
	}

	if len(rows) == 0 {
		return
	}

	renderSingleCategory(writer, categoryName, tableWriter, rows, infoToPrintInfo)

}

func (cp *ClusterPrinter) generateCountingCategoryRow(controlSummary reportsummary.IControlSummary) table.Row {

	row := make(table.Row, 3)

	row[0] = controlSummary.GetName()

	failedResources := controlSummary.NumberOfResources().Failed()
	if failedResources > 0 {
		row[1] = gchalk.WithYellow().Bold(fmt.Sprintf("%d", failedResources))
	} else {
		row[1] = fmt.Sprintf("%d", failedResources)
	}

	row[2] = cp.generateTableNextSteps(controlSummary)

	return row
}

func (cp *ClusterPrinter) generateTableNextSteps(controlSummary reportsummary.IControlSummary) string {
	return fmt.Sprintf("%s %s -v", scanControlPrefix, controlSummary.GetID())
}
