package printer

import (
	"fmt"
	"os"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/olekukonko/tablewriter"
)

const (
	categoriesColumnSeverity  = iota
	categoriesColumnName      = iota
	categoriesColumnFailed    = iota
	categoriesColumnNextSteps = iota
)

var (
	mapScanTypeToOutput = map[cautils.ScanTypes]string{
		cautils.ScanTypeCluster: "Security Overview",
	}
)

func generateCategoriesRow(controlSummary reportsummary.IControlSummary) []string {
	row := make([]string, 4)
	row[categoriesColumnSeverity] = getSeverityColumn(controlSummary)

	if len(controlSummary.GetName()) > 50 {
		row[categoriesColumnName] = controlSummary.GetName()[:50] + "..."
	} else {
		row[categoriesColumnName] = controlSummary.GetName()
	}

	row[categoriesColumnFailed] = fmt.Sprintf("%d", controlSummary.NumberOfResources().Failed())
	row[categoriesColumnNextSteps] = generateNextSteps(controlSummary)

	return row
}

func generateNextSteps(controlSummary reportsummary.IControlSummary) string {
	return fmt.Sprintf("kubescape scan control %s", controlSummary.GetID())
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

func renderSingleCategory(writer *os.File, category string, ctrls []reportsummary.IControlSummary, categoriesTable *tablewriter.Table) {
	cautils.InfoTextDisplay(writer, "\n"+category+"\n")

	var rows [][]string
	for i := range ctrls {
		row := generateCategoriesRow(ctrls[i])
		if len(row) > 0 {
			rows = append(rows, row)
		}
	}
	categoriesTable.ClearRows()
	categoriesTable.AppendBulk(rows)
	categoriesTable.Render()
}
