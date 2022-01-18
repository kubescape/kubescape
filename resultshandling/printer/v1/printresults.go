package v1

import (
	"github.com/armosec/kubescape/resultshandling/printer"
	"github.com/armosec/kubescape/resultshandling/printer/v2/controlmapping"
)

var INDENT = "   "

func GetPrinter(printFormat string, verboseMode bool) printer.IPrinter {
	switch printFormat {
	case printer.JsonFormat:
		return NewJsonPrinter()
	case printer.JunitResultFormat:
		return NewJunitPrinter()
	case printer.PrometheusFormat:
		return NewPrometheusPrinter(verboseMode)
	default:
		return controlmapping.NewPrettyPrinter(verboseMode)
	}
}
