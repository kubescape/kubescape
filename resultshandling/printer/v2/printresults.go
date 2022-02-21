package v2

import (
	"github.com/armosec/kubescape/resultshandling/printer"
	"github.com/armosec/kubescape/resultshandling/printer/v2/resourcemapping"
)

var INDENT = "   "

func GetPrinter(printFormat string, verboseMode bool) printer.IPrinter {
	switch printFormat {
	case printer.JsonFormat:
		return resourcemapping.NewJsonPrinter()
	case printer.JunitResultFormat:
		return NewJunitPrinter()
	// case printer.PrometheusFormat:
	// 	return NewPrometheusPrinter(verboseMode)
	case printer.PdfFormat:
		return NewPdfPrinter()
	default:
		return resourcemapping.NewPrettyPrinter(verboseMode)
	}
}
