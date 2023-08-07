package configurationprinter

import (
	"io"

	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

type TablePrinter interface {
	PrintCategoriesTables(writer io.Writer, summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string)
	PrintSummaryTable(writer io.Writer, summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string)
}
