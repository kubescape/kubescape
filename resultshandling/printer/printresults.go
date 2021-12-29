package printer

import (
	"github.com/armosec/kubescape/cautils"
)

var INDENT = "   "

const (
	PrettyFormat      string = "pretty-printer"
	JsonFormat        string = "json"
	JunitResultFormat string = "junit"
	PrometheusFormat  string = "prometheus"
)

type IPrinter interface {
	ActionPrint(opaSessionObj *cautils.OPASessionObj)
	SetWriter(outputFile string)
	Score(score float32)
}

func GetPrinter(printFormat string, verboseMode bool) IPrinter {
	switch printFormat {
	case JsonFormat:
		return NewJsonPrinter()
	case JunitResultFormat:
		return NewJunitPrinter()
	case PrometheusFormat:
		return NewPrometheusPrinter(verboseMode)
	default:
		return NewPrettyPrinter(verboseMode)
	}
}
