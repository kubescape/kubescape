package resultshandling

import (
	"context"
	"testing"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

type DummyReporter struct{}

func (dr *DummyReporter) Submit(_ context.Context, opaSessionObj *cautils.OPASessionObj) error {
	return nil
}
func (dr *DummyReporter) SetCustomerGUID(customerGUID string) {}
func (dr *DummyReporter) SetClusterName(clusterName string)   {}
func (dr *DummyReporter) DisplayReportURL()                   {}
func (dr *DummyReporter) GetURL() string                      { return "" }

type SpyPrinter struct {
	ActionPrintCalls int
	ScoreCalls       int
}

func (sp *SpyPrinter) SetWriter(_ context.Context, outputFile string) {}
func (sp *SpyPrinter) PrintNextSteps()                                {}
func (sp *SpyPrinter) ActionPrint(_ context.Context, opaSessionObj *cautils.OPASessionObj, _ []cautils.ImageScanData) {
	sp.ActionPrintCalls += 1
}
func (sp *SpyPrinter) Score(score float32) {
	sp.ScoreCalls += 1
}

func TestResultsHandlerHandleResultsPrintsResultsToUI(t *testing.T) {
	reporter := &DummyReporter{}
	printers := []printer.IPrinter{}
	uiPrinter := &SpyPrinter{}
	fakeScanData := &cautils.OPASessionObj{
		Report: &reporthandlingv2.PostureReport{
			SummaryDetails: reportsummary.SummaryDetails{
				Score: 0.0,
			},
		},
	}

	rh := NewResultsHandler(reporter, printers, uiPrinter)
	rh.SetData(fakeScanData)

	rh.HandleResults(context.TODO())

	want := 1
	got := uiPrinter.ActionPrintCalls
	if got != want {
		t.Errorf("UI Printer was not called to print. Got calls: %d, want calls: %d", got, want)
	}
}

func TestValidatePrinter(t *testing.T) {
	tests := []struct {
		name     string
		scanType cautils.ScanTypes
		format   string
		expected bool
	}{
		{
			name:     "json format for cluster scan",
			scanType: cautils.ScanTypeCluster,
			format:   printer.JsonFormat,
			expected: true,
		},
		{
			name:     "junit format for cluster scan",
			scanType: cautils.ScanTypeCluster,
			format:   printer.JunitResultFormat,
			expected: true,
		},
		{
			name:     "sarif format for cluster scan",
			scanType: cautils.ScanTypeCluster,
			format:   printer.SARIFFormat,
			expected: true,
		},
		{
			name:     "pretty format for cluster scan",
			scanType: cautils.ScanTypeCluster,
			format:   printer.PrettyFormat,
			expected: true,
		},
		{
			name:     "html format for cluster scan",
			scanType: cautils.ScanTypeCluster,
			format:   printer.HtmlFormat,
			expected: true,
		},
		{
			name:     "prometheus format for cluster scan",
			scanType: cautils.ScanTypeCluster,
			format:   printer.PrometheusFormat,
			expected: true,
		},

		{
			name:     "json format for image scan",
			scanType: cautils.ScanTypeImage,
			format:   printer.JsonFormat,
			expected: true,
		},
		{
			name:     "junit format for image scan",
			scanType: cautils.ScanTypeImage,
			format:   printer.JunitResultFormat,
			expected: false,
		},
		{
			name:     "sarif format for image scan",
			scanType: cautils.ScanTypeImage,
			format:   printer.SARIFFormat,
			expected: true,
		},
		{
			name:     "pretty format for image scan",
			scanType: cautils.ScanTypeImage,
			format:   printer.PrettyFormat,
			expected: true,
		},
		{
			name:     "html format for image scan",
			scanType: cautils.ScanTypeImage,
			format:   printer.HtmlFormat,
			expected: false,
		},
		{
			name:     "prometheus format for image scan",
			scanType: cautils.ScanTypeImage,
			format:   printer.PrometheusFormat,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidatePrinter(tt.scanType, tt.format)
			if got != tt.expected {
				t.Errorf("%s failed - got = %v, want %v", tt.name, got, tt.expected)
			}
		})
	}

}
