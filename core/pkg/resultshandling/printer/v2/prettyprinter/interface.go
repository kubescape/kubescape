package prettyprinter

import (
	"os"

	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

type MainPrinter interface {
	Print(writer *os.File, summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string)
}
