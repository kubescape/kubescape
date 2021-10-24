package printer

import (
	"github.com/armosec/kubescape/cautils"
)

var INDENT = "   "

const EmptyPercentage = "NaN"

const (
	PrettyFormat       string = "pretty-printer"
	JsonFormat         string = "json"
	JunitResultPrinter string = "junit"
)

type IPrinter interface {
	ActionPrint(opaSessionObj *cautils.OPASessionObj)
	SetWriter(outputFile string)
}

func GetPrinter(printFormat string) IPrinter {
	switch printFormat {
	case JsonFormat:
		return NewJsonPrinter()
	case JunitResultPrinter:
		return NewJunitPrinter()
	default:
		return NewPrettyPrinter()
	}
}
