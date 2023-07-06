package printer

import (
	"fmt"
	"os"

	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/olekukonko/tablewriter"
)

type clusterPrinter struct {
}

var _ mainPrinter = &clusterPrinter{}

func NewClusterPrinter() *clusterPrinter {
	return &clusterPrinter{}
}

func (cp *clusterPrinter) PrintMainTable(writer *os.File, summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {
	categoriesToControlSummariesMap := mapCategoryToControlSummaries(*summaryDetails)

	categoriesTable := tablewriter.NewWriter(writer)
	categoriesTable.SetHeader(getCategoriesTableHeaders())
	categoriesTable.SetHeaderLine(true)
	categoriesTable.SetColumnAlignment(getCategoriesColumnsAlignments())

	for category, ctrls := range categoriesToControlSummariesMap {
		renderSingleCategory(writer, category, ctrls, categoriesTable)
	}
	fmt.Println("")
}
