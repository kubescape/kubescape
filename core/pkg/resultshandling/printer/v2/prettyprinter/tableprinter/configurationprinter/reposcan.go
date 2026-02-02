package configurationprinter

import (
	"fmt"
	"io"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jwalton/gchalk"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
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

func (rp *RepoPrinter) PrintSummaryTable(_ io.Writer, _ *reportsummary.SummaryDetails, _ [][]string) {

}

func (rp *RepoPrinter) PrintCategoriesTables(writer io.Writer, summaryDetails *reportsummary.SummaryDetails, _ [][]string) {

	categoriesToCategoryControls := mapCategoryToSummary(summaryDetails.ListControls(), mapRepoControlsToCategories)

	tableRendered := false
	for _, id := range repoCategoriesDisplayOrder {
		categoryControl, ok := categoriesToCategoryControls[id]
		if !ok {
			continue
		}

		if categoryControl.Status != apis.StatusFailed {
			continue
		}

		tableRendered = tableRendered || rp.renderSingleCategoryTable(categoryControl.CategoryName, mapCategoryToType[id], writer, categoryControl.controlSummaries, utils.MapInfoToPrintInfoFromIface(categoryControl.controlSummaries))
	}

	if !tableRendered {
		fmt.Fprintln(writer, gchalk.WithGreen().Bold("All controls passed. No issues found"))
	}

}

func (rp *RepoPrinter) renderSingleCategoryTable(categoryName string, categoryType CategoryType, writer io.Writer, controlSummaries []reportsummary.IControlSummary, infoToPrintInfo []utils.InfoStars) bool {
	sortControlSummaries(controlSummaries)

	headers, columnAlignments := initCategoryTableData(categoryType)

	tableWriter := getCategoryTableWriter(writer, headers, columnAlignments)

	var rows []table.Row
	for _, ctrls := range controlSummaries {
		if ctrls.NumberOfResources().Failed() == 0 {
			continue
		}

		var row table.Row
		if categoryType == TypeCounting {
			row = rp.generateCountingCategoryRow(ctrls, rp.inputPatterns)
		} else {
			row = generateCategoryStatusRow(ctrls)
		}
		if len(row) > 0 {
			rows = append(rows, row)
		}
	}

	if len(rows) == 0 {
		return false
	}

	renderSingleCategory(writer, categoryName, tableWriter, rows, infoToPrintInfo)
	return true
}

func (rp *RepoPrinter) generateCountingCategoryRow(controlSummary reportsummary.IControlSummary, inputPatterns []string) table.Row {
	rows := make(table.Row, 3)

	rows[0] = controlSummary.GetName()

	failedResources := controlSummary.NumberOfResources().Failed()
	if failedResources > 0 {
		rows[1] = gchalk.WithYellow().Bold(fmt.Sprintf("%d", failedResources))
	} else {
		rows[1] = fmt.Sprintf("%d", failedResources)
	}

	rows[2] = rp.generateTableNextSteps(controlSummary, inputPatterns)

	return rows
}

func (rp *RepoPrinter) generateTableNextSteps(controlSummary reportsummary.IControlSummary, inputPatterns []string) string {
	return fmt.Sprintf("$ kubescape scan control %s %s -v", controlSummary.GetID(), strings.Join(inputPatterns, ","))
}
