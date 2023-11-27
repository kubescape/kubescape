package resultshandling

import (
	"context"
	"errors"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
)

type DummyReporter struct{}

func (dr *DummyReporter) Submit(_ context.Context, opaSessionObj *cautils.OPASessionObj) error {
	return nil
}
func (dr *DummyReporter) SetTenantConfig(tenantConfig cautils.ITenantConfig) {}
func (dr *DummyReporter) DisplayMessage()                                    {}
func (dr *DummyReporter) GetURL() string                                     { return "" }

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
		name        string
		scanType    cautils.ScanTypes
		scanContext cautils.ScanningContext
		format      string
		expectErr   error
	}{
		{
			name:      "json format for cluster scan should not return error",
			scanType:  cautils.ScanTypeCluster,
			format:    printer.JsonFormat,
			expectErr: nil,
		},
		{
			name:      "junit format for cluster scan should return error",
			scanType:  cautils.ScanTypeCluster,
			format:    printer.JunitResultFormat,
			expectErr: nil,
		},
		{
			name:        "sarif format for cluster scan and git url context should not return error",
			scanType:    cautils.ScanTypeCluster,
			scanContext: cautils.ContextGitLocal,
			format:      printer.SARIFFormat,
			expectErr:   nil,
		},
		{
			name:      "pretty format for cluster scan should not return error",
			scanType:  cautils.ScanTypeCluster,
			format:    printer.PrettyFormat,
			expectErr: nil,
		},
		{
			name:      "html format for cluster scan should not return error",
			scanType:  cautils.ScanTypeCluster,
			format:    printer.HtmlFormat,
			expectErr: nil,
		},
		{
			name:      "prometheus format for cluster scan should not return error",
			scanType:  cautils.ScanTypeCluster,
			format:    printer.PrometheusFormat,
			expectErr: nil,
		},

		{
			name:      "json format for image scan should not return error",
			scanType:  cautils.ScanTypeImage,
			format:    printer.JsonFormat,
			expectErr: nil,
		},
		{
			name:      "junit format for image scan should return error",
			scanType:  cautils.ScanTypeImage,
			format:    printer.JunitResultFormat,
			expectErr: errors.New("format \"junit\"is not supported for image scanning"),
		},
		{
			name:      "sarif format for image scan should not return error",
			scanType:  cautils.ScanTypeImage,
			format:    printer.SARIFFormat,
			expectErr: nil,
		},
		{
			name:      "pretty format for image scan should not return error",
			scanType:  cautils.ScanTypeImage,
			format:    printer.PrettyFormat,
			expectErr: nil,
		},
		{
			name:      "html format for image scan should return error",
			scanType:  cautils.ScanTypeImage,
			format:    printer.HtmlFormat,
			expectErr: errors.New("format \"html\"is not supported for image scanning"),
		},
		{
			name:      "prometheus format for image scan should return error",
			scanType:  cautils.ScanTypeImage,
			format:    printer.PrometheusFormat,
			expectErr: errors.New("format \"prometheus\"is not supported for image scanning"),
		},
		{
			name:        "sarif format for cluster context should return error",
			scanContext: cautils.ContextCluster,
			format:      printer.SARIFFormat,
			expectErr:   errors.New("format \"sarif\" is only supported when scanning local files"),
		},
		{
			name:        "sarif format for remote url context should return error",
			scanContext: cautils.ContextGitURL,
			format:      printer.SARIFFormat,
			expectErr:   errors.New("format \"sarif\" is only supported when scanning local files"),
		},
		{
			name:        "sarif format for local dir context should not return error",
			scanContext: cautils.ContextDir,
			format:      printer.SARIFFormat,
			expectErr:   nil,
		},
		{
			name:        "sarif format for local file context should not return error",
			scanContext: cautils.ContextFile,
			format:      printer.SARIFFormat,
			expectErr:   nil,
		},
		{
			name:        "sarif format for local git context should not return error",
			scanContext: cautils.ContextGitLocal,
			format:      printer.SARIFFormat,
			expectErr:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidatePrinter(tt.scanType, tt.scanContext, tt.format)

			assert.Equal(t, tt.expectErr, got)
		})
	}
}

func TestNewPrinter(t *testing.T) {
	defaultVersion := "v2"
	ctx := context.Background()
	tests := []struct {
		name     string
		format   string
		viewType string
		version  string
	}{
		{
			name:     "JSON printer v1",
			format:   "json",
			viewType: "resource",
			version:  "v1",
		},
		{
			name:     "JSON printer v2",
			format:   "json",
			viewType: "resource",
			version:  defaultVersion,
		},
		{
			name:     "JSON printer unknown v3",
			format:   "json",
			viewType: "resource",
			version:  "v3",
		},
		{
			name:     "JUNIT printer",
			format:   "junit",
			viewType: "resource",
			version:  defaultVersion,
		},
		{
			name:     "Prometheus printer",
			format:   "prometheus",
			viewType: "control",
			version:  defaultVersion,
		},
		{
			name:     "Pdf printer",
			format:   "pdf",
			viewType: "security",
			version:  defaultVersion,
		},
		{
			name:     "HTML printer",
			format:   "html",
			viewType: "control",
			version:  defaultVersion,
		},
		{
			name:     "Sarif printer",
			format:   "sarif",
			viewType: "resource",
			version:  defaultVersion,
		},
		{
			name:     "Prettry printer",
			format:   "pretty-printer",
			viewType: "control",
			version:  defaultVersion,
		},
		{
			name:     "Invalid format printer",
			format:   "pretty",
			viewType: "security",
			version:  defaultVersion,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanInfo := &cautils.ScanInfo{
				Format:        tt.format,
				FormatVersion: tt.version,
				View:          tt.viewType,
			}
			printer := NewPrinter(ctx, tt.format, scanInfo, "my-cluster")
			assert.NotNil(t, printer)
		})
	}
}
