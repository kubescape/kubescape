package configurationprinter

import (
	"fmt"
	"io"
	"strings"

	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
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

func (rp *RepoPrinter) PrintCategoriesTables(writer io.Writer, summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {

	categoriesToCategoryControls := mapCategoryToSummary(summaryDetails.ListControls(), mapClusterControlsToCategories)

	for _, id := range categoriesDisplayOrder {
		categoryControl, ok := categoriesToCategoryControls[id]
		if !ok {
			continue
		}

		infoToPrintInfo := utils.MapInfoToPrintInfoFromIface(categoryControl.controlSummaries)

		rp.renderSingleCategoryTable(categoryControl.CategoryName, mapCategoryToType[id], writer, categoryControl.controlSummaries, infoToPrintInfo)
	}

}

func (rp *RepoPrinter) renderSingleCategoryTable(categoryName string, categoryType CategoryType, writer io.Writer, controlSummaries []reportsummary.IControlSummary, infoToPrintInfo []utils.InfoStars) {
	headers, columnAligments := initCategoryTableData(categoryType)

	table := getCategoryTableWriter(writer, headers, columnAligments)

	var rows [][]string
	for _, ctrls := range controlSummaries {
		var row []string
		if categoryType == TypeCounting {
			row = rp.generateCountingCategoryRow(ctrls, rp.inputPatterns)
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

func (rp *RepoPrinter) generateCountingCategoryRow(controlSummary reportsummary.IControlSummary, inputPatterns []string) []string {
	rows := make([]string, 3)

	rows[0] = controlSummary.GetName()

	rows[1] = fmt.Sprintf("%d", controlSummary.NumberOfResources().Failed())

	rows[2] = rp.generateTableNextSteps(controlSummary, inputPatterns)

	return rows
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
