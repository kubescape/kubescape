package printer

import (
	"context"
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

var _ printer.IPrinter = &PrometheusPrinter{}

type PrometheusPrinter struct {
	writer      *os.File
	verboseMode bool
}

func NewPrometheusPrinter(verboseMode bool) *PrometheusPrinter {
	return &PrometheusPrinter{
		verboseMode: verboseMode,
	}
}

func (pp *PrometheusPrinter) SetWriter(ctx context.Context, outputFile string) {
	pp.writer = printer.GetWriter(ctx, outputFile)
}

func (pp *PrometheusPrinter) Score(score float32) {
	fmt.Printf("\n# Overall risk-score (0- Excellent, 100- All failed)\nkubescape_score %d\n", cautils.Float32ToInt(score))
}

func (pp *PrometheusPrinter) generatePrometheusFormat(
	resources map[string]workloadinterface.IMetadata,
	results map[string]resourcesresults.Result,
	summaryDetails *reportsummary.SummaryDetails) *Metrics {

	m := &Metrics{}
	m.setRiskScores(summaryDetails)
	// m.setResourcesCounters(resources, results)

	return m
}

func (pp *PrometheusPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj) {

	metrics := pp.generatePrometheusFormat(opaSessionObj.AllResources, opaSessionObj.ResourcesResult, &opaSessionObj.Report.SummaryDetails)

	if _, err := pp.writer.Write([]byte(metrics.String())); err != nil {
		logger.L().Ctx(ctx).Error("failed to write results", helpers.Error(err))
	} else {
		printer.LogOutputFile(pp.writer.Name())
	}
}
