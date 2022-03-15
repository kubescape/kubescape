package v2

import (
	"fmt"
	"os"

	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/kubescape/core/cautils"
	"github.com/armosec/kubescape/core/cautils/logger"
	"github.com/armosec/kubescape/core/cautils/logger/helpers"
	"github.com/armosec/kubescape/core/pkg/resultshandling/printer"
	"github.com/armosec/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/armosec/opa-utils/reporthandling/results/v1/resourcesresults"
)

type PrometheusPrinter struct {
	writer      *os.File
	verboseMode bool
}

func NewPrometheusPrinter(verboseMode bool) *PrometheusPrinter {
	return &PrometheusPrinter{
		verboseMode: verboseMode,
	}
}

func (prometheusPrinter *PrometheusPrinter) SetWriter(outputFile string) {
	prometheusPrinter.writer = printer.GetWriter(outputFile)
}

func (prometheusPrinter *PrometheusPrinter) Score(score float32) {
	fmt.Printf("\n# Overall risk-score (0- Excellent, 100- All failed)\nkubescape_score %d\n", int(score))
}

func (printer *PrometheusPrinter) generatePrometheusFormat(
	resources map[string]workloadinterface.IMetadata,
	results map[string]resourcesresults.Result,
	summaryDetails *reportsummary.SummaryDetails) *Metrics {

	m := &Metrics{}
	m.setRiskScores(summaryDetails)
	m.setResourcesCounters(resources, results)

	return m
}

func (printer *PrometheusPrinter) ActionPrint(opaSessionObj *cautils.OPASessionObj) {

	metrics := printer.generatePrometheusFormat(opaSessionObj.AllResources, opaSessionObj.ResourcesResult, &opaSessionObj.Report.SummaryDetails)

	logOUtputFile(printer.writer.Name())
	if _, err := printer.writer.Write([]byte(metrics.String())); err != nil {
		logger.L().Error("failed to write results", helpers.Error(err))
	}
}
