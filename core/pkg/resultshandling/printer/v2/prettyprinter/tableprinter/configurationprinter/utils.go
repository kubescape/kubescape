package configurationprinter

import (
	"fmt"
	"io"

	"github.com/fatih/color"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/olekukonko/tablewriter"
)

func GetSeverityColumn(controlSummary reportsummary.IControlSummary) string {
	return color.New(utils.GetColor(apis.ControlSeverityToInt(controlSummary.GetScoreFactor())), color.Bold).SprintFunc()(apis.ControlSeverityToString(controlSummary.GetScoreFactor()))
}

type InfoStars struct {
	Stars string
	Info  string
}

func ControlCountersForSummary(counters reportsummary.ICounters) string {
	return fmt.Sprintf("Controls: %d (Failed: %d, Passed: %d, Action Required: %d)", counters.All(), counters.Failed(), counters.Passed(), counters.Skipped())
}

func getCommonColumnsAlignments() []int {
	return []int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_LEFT}
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

func getTableWriter(writer io.Writer, headers []string, columnAligments []int) *tablewriter.Table {
	table := tablewriter.NewWriter(writer)
	table.SetHeader(headers)
	table.SetHeaderLine(true)
	table.SetColumnAlignment(columnAligments)
	return table
}

func renderCategoriesTable(mapCategoryToRows map[string][][]string, writer io.Writer, table *tablewriter.Table) {
	for category, rows := range mapCategoryToRows {
		cautils.InfoTextDisplay(writer, "\n"+category+"\n")

		table.ClearRows()
		table.AppendBulk(rows)

		table.Render()

		cautils.SimpleDisplay(writer, "\n")
	}
}
