package printer

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
)

const (
	prometheusOutputFile = "report"
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

func (pp *PrometheusPrinter) PrintNextSteps() {

}

func (pp *PrometheusPrinter) SetWriter(ctx context.Context, outputFile string) error {
	explicitOutput := outputFile != ""
	if outputFile != "" {
		outputFile = strings.TrimSpace(outputFile)
		if outputFile == "" {
			outputFile = prometheusOutputFile
		}
		if !printer.HasOutputExt(outputFile, printer.PrometheusOutputExt) {
			outputFile = outputFile + printer.PrometheusOutputExt
		}
	}
	if explicitOutput {
		var err error
		pp.writer, err = printer.GetWriterNoFallback(outputFile)
		return err
	}
	pp.writer = printer.GetWriter(ctx, outputFile)
	return nil
}

func (pp *PrometheusPrinter) Score(score float32) {
	// Handle invalid scores
	if score > 100 {
		score = 100
	} else if score < 0 {
		score = 0
	}

	fmt.Fprintf(pp.writer, "# HELP kubescape_score Overall compliance score (100 Excellent, 0 All failed)\n")
	fmt.Fprintf(pp.writer, "# TYPE kubescape_score gauge\n")
	fmt.Fprintf(pp.writer, "kubescape_score %d\n", cautils.ComplianceScoreToInt(score))
}

func (pp *PrometheusPrinter) generatePrometheusFormat(
	resources map[string]workloadinterface.IMetadata,
	results map[string]resourcesresults.Result,
	summaryDetails *reportsummary.SummaryDetails,
	coverage cautils.ScanCoverage) *Metrics {

	m := &Metrics{}
	m.setComplianceScores(summaryDetails)
	m.setResourcesCounters(resources, results)
	m.setCoverageScore(coverage)

	return m
}

// generateImagePrometheusFormat builds CVE-count metrics, grouped by image and severity, for an image scan (#2782)
func (pp *PrometheusPrinter) generateImagePrometheusFormat(imageScanData []cautils.ImageScanData) *Metrics {
	m := &Metrics{isImageScan: true}
	m.setImageVulnerabilities(imageScanData)
	return m
}

func (pp *PrometheusPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) error {
	var metrics *Metrics

	if opaSessionObj != nil {
		metrics = pp.generatePrometheusFormat(opaSessionObj.AllResources, opaSessionObj.ResourcesResult, &opaSessionObj.Report.SummaryDetails, opaSessionObj.ScanCoverage)
	} else if len(imageScanData) > 0 {
		metrics = pp.generateImagePrometheusFormat(imageScanData)
	} else {
		return fmt.Errorf("failed to print results, missing data")
	}

	if _, err := pp.writer.Write([]byte(metrics.String())); err != nil {
		logger.L().Ctx(ctx).Error("failed to write results", helpers.Error(err))
		return fmt.Errorf("failed to write results: %w", err)
	}
	printer.LogOutputFile(pp.writer.Name())
	return nil
}

// CloseWriter closes the Prometheus output writer, returning any error from flushing or closing.
func (p *PrometheusPrinter) CloseWriter() error {
	if p.writer != nil && p.writer != os.Stdout {
		return p.writer.Close()
	}
	return nil
}
