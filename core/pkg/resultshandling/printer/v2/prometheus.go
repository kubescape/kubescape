package v2

import (
	"fmt"
	"os"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
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
	fmt.Printf("\n# Overall risk-score (0- Excellent, 100- All failed)\nkubescape_score %d\n", cautils.Float32ToInt(score))
}

func (prometheusPrinter *PrometheusPrinter) generatePrometheusFormat(
	resources map[string]workloadinterface.IMetadata,
	results map[string]resourcesresults.Result,
	summaryDetails *reportsummary.SummaryDetails) *Metrics {

	m := &Metrics{}
	m.setRiskScores(summaryDetails)
	// m.setResourcesCounters(resources, results)

	return m
}

func (prometheusPrinter *PrometheusPrinter) ActionPrint(opaSessionObj *cautils.OPASessionObj) {

	metrics := prometheusPrinter.generatePrometheusFormat(opaSessionObj.AllResources, opaSessionObj.ResourcesResult, &opaSessionObj.Report.SummaryDetails)

	if _, err := prometheusPrinter.writer.Write([]byte(metrics.String())); err != nil {
		logger.L().Error("failed to write results", helpers.Error(err))
	} else {
		printer.LogOutputFile(prometheusPrinter.writer.Name())
	}
}
