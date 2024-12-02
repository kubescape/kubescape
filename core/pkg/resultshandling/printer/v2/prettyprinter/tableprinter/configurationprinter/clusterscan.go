package configurationprinter

import (
	"fmt"
	"io"

	"github.com/jwalton/gchalk"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

type ClusterPrinter struct{}

func NewClusterPrinter() *ClusterPrinter {
	return &ClusterPrinter{}
}

var _ TablePrinter = &ClusterPrinter{}

func (cp *ClusterPrinter) PrintSummaryTable(writer io.Writer, summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {

}

func (cp *ClusterPrinter) PrintCategoriesTables(writer io.Writer, summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {

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

	headers, columnAligments := initCategoryTableData(categoryType)

	table := getCategoryTableWriter(writer, headers, columnAligments)

	var rows [][]string
	for _, ctrls := range controlSummaries {
		var row []string
		if categoryType == TypeCounting {
			row = cp.generateCountingCategoryRow(ctrls)
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

func (cp *ClusterPrinter) generateCountingCategoryRow(controlSummary reportsummary.IControlSummary) []string {

	row := make([]string, 3)

	row[0] = controlSummary.GetName()

	failedResources := controlSummary.NumberOfResources().Failed()
	if failedResources > 0 {
		row[1] = string(gchalk.WithYellow().Bold(fmt.Sprintf("%d", failedResources)))
	} else {
		row[1] = fmt.Sprintf("%d", failedResources)
	}

	row[2] = cp.generateTableNextSteps(controlSummary)

	return row
}

func (cp *ClusterPrinter) generateTableNextSteps(controlSummary reportsummary.IControlSummary) string {
	return fmt.Sprintf("%s %s -v", scanControlPrefix, controlSummary.GetID())
}
