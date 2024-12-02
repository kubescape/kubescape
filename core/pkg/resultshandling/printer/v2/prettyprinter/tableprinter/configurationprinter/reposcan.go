package configurationprinter

import (
	"fmt"
	"io"
	"strings"

	"github.com/jwalton/gchalk"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
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

	categoriesToCategoryControls := mapCategoryToSummary(summaryDetails.ListControls(), mapRepoControlsToCategories)

	tableRended := false
	for _, id := range repoCategoriesDisplayOrder {
		categoryControl, ok := categoriesToCategoryControls[id]
		if !ok {
			continue
		}

		if categoryControl.Status != apis.StatusFailed {
			continue
		}

		tableRended = tableRended || rp.renderSingleCategoryTable(categoryControl.CategoryName, mapCategoryToType[id], writer, categoryControl.controlSummaries, utils.MapInfoToPrintInfoFromIface(categoryControl.controlSummaries))
	}

	if !tableRended {
		fmt.Fprintln(writer, gchalk.WithGreen().Bold("All controls passed. No issues found"))
	}

}

func (rp *RepoPrinter) renderSingleCategoryTable(categoryName string, categoryType CategoryType, writer io.Writer, controlSummaries []reportsummary.IControlSummary, infoToPrintInfo []utils.InfoStars) bool {
	sortControlSummaries(controlSummaries)

	headers, columnAligments := initCategoryTableData(categoryType)

	table := getCategoryTableWriter(writer, headers, columnAligments)

	var rows [][]string
	for _, ctrls := range controlSummaries {
		if ctrls.NumberOfResources().Failed() == 0 {
			continue
		}

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
		return false
	}

	renderSingleCategory(writer, categoryName, table, rows, infoToPrintInfo)
	return true
}

func (rp *RepoPrinter) generateCountingCategoryRow(controlSummary reportsummary.IControlSummary, inputPatterns []string) []string {
	rows := make([]string, 3)

	rows[0] = controlSummary.GetName()

	failedResources := controlSummary.NumberOfResources().Failed()
	if failedResources > 0 {
		rows[1] = string(gchalk.WithYellow().Bold(fmt.Sprintf("%d", failedResources)))
	} else {
		rows[1] = fmt.Sprintf("%d", failedResources)
	}

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
	return fmt.Sprintf("$ kubescape scan control %s %s -v", controlSummary.GetID(), strings.Join(inputPatterns, ","))
}
