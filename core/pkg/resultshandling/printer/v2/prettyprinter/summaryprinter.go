package prettyprinter

const (
	summaryColumnSeverity        = iota
	summaryColumnName            = iota
	summaryColumnCounterFailed   = iota
	summaryColumnCounterAll      = iota
	summaryColumnComplianceScore = iota
	_summaryRowLen               = iota
)

func NewSummaryPrinter() *MainPrinterImpl {
	printer := &MainPrinterImpl{}
	printer.SetSummaryPrint(true)

	return printer
}
