package prettyprinter

import "github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"

type MainPrinter interface {
	Print(*reportsummary.SummaryDetails, [][]string)
}
