package v2

import "github.com/armosec/kubescape/resultshandling/printer"

var INDENT = "   "

func GetPrinter(printFormat string, verboseMode bool) printer.IPrinter {
	switch printFormat {
	case printer.JsonFormat:
		return NewJsonPrinter()
	case printer.JunitResultFormat:
		return NewJunitPrinter()
	// case printer.PrometheusFormat:
	// 	return NewPrometheusPrinter(verboseMode)
	default:
		return NewPrettyPrinter(verboseMode)
	}
}
