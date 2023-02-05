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
func (sp *SpyPrinter) ActionPrint(_ context.Context, opaSessionObj *cautils.OPASessionObj) {
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

func TestResultsHandlerHandleResultsPrintsScoreToUI(t *testing.T) {
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
	got := uiPrinter.ScoreCalls
	if got != want {
		t.Errorf("UI Printer was not called to print. Got calls: %d, want calls: %d", got, want)
	}
}
