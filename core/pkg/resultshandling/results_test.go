package resultshandling

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
)

type DummyReporter struct{}

func (dr *DummyReporter) Submit(_ context.Context, _ *cautils.OPASessionObj) error {
	return nil
}
func (dr *DummyReporter) SetTenantConfig(_ cautils.ITenantConfig) {}
func (dr *DummyReporter) DisplayMessage()                         {}
func (dr *DummyReporter) GetURL() string                          { return "" }

type SpyPrinter struct {
	ActionPrintCalls int
	ScoreCalls       int
}

func (sp *SpyPrinter) SetWriter(_ context.Context, _ string) {}
func (sp *SpyPrinter) PrintNextSteps()                       {}
func (sp *SpyPrinter) ActionPrint(_ context.Context, _ *cautils.OPASessionObj, _ []cautils.ImageScanData) {
	sp.ActionPrintCalls += 1
}
func (sp *SpyPrinter) Score(_ float32) {
	sp.ScoreCalls += 1
}

func TestResultsHandlerHandleResultsPrintsResultsToUI(t *testing.T) {
	reporter := &DummyReporter{}
	var printers []printer.IPrinter
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

	err := rh.HandleResults(context.Background(), &cautils.ScanInfo{})
	assert.NoError(t, err)

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
			expectErr: errors.New("format \"junit\" is not supported for image scanning"),
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
			expectErr: errors.New("format \"html\" is not supported for image scanning"),
		},
		{
			name:      "prometheus format for image scan should return error",
			scanType:  cautils.ScanTypeImage,
			format:    printer.PrometheusFormat,
			expectErr: errors.New("format \"prometheus\" is not supported for image scanning"),
		},
		{
			name:        "sarif format for cluster context should return error",
			scanContext: cautils.ContextCluster,
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
		{
			name:      "pdf format for image scan should return error",
			scanType:  cautils.ScanTypeImage,
			format:    printer.PdfFormat,
			expectErr: errors.New("format \"pdf\" is not supported for image scanning"),
		},
		{
			name:      "pdf format for cluster scan should not return error",
			scanType:  cautils.ScanTypeCluster,
			format:    printer.PdfFormat,
			expectErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got := ValidatePrinter(tt.scanType, tt.scanContext, tt.format)

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
			name:     "Pretty printer",
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
			p := NewPrinter(ctx, tt.format, scanInfo, "my-cluster")
			assert.NotNil(t, p)
		})
	}
}

func makeResultsHandler(complianceScore, riskScore float32) *ResultsHandler {
	fakeScanData := &cautils.OPASessionObj{
		Report: &reporthandlingv2.PostureReport{
			SummaryDetails: reportsummary.SummaryDetails{
				Score:           riskScore,
				ComplianceScore: complianceScore,
			},
		},
		Metadata: &reporthandlingv2.Metadata{},
	}
	rh := NewResultsHandler(&DummyReporter{}, nil, &SpyPrinter{})
	rh.SetData(fakeScanData)
	return rh
}

func TestGetComplianceScore(t *testing.T) {
	tests := []struct {
		name            string
		complianceScore float32
		want            float32
	}{
		{name: "zero score", complianceScore: 0, want: 0},
		{name: "full score", complianceScore: 100, want: 100},
		{name: "partial score", complianceScore: 67.5, want: 67.5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rh := makeResultsHandler(tt.complianceScore, 0)
			assert.Equal(t, tt.want, rh.GetComplianceScore())
		})
	}
}

func TestGetRiskScore(t *testing.T) {
	tests := []struct {
		name      string
		riskScore float32
		want      float32
	}{
		{name: "zero risk", riskScore: 0, want: 0},
		{name: "full risk", riskScore: 100, want: 100},
		{name: "partial risk", riskScore: 42.0, want: 42.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rh := makeResultsHandler(0, tt.riskScore)
			assert.Equal(t, tt.want, rh.GetRiskScore())
		})
	}
}

func TestSetDataGetData(t *testing.T) {
	rh := NewResultsHandler(&DummyReporter{}, nil, &SpyPrinter{})
	assert.Nil(t, rh.GetData())

	data := &cautils.OPASessionObj{
		Report: &reporthandlingv2.PostureReport{
			SummaryDetails: reportsummary.SummaryDetails{
				ComplianceScore: 55.0,
			},
		},
	}
	rh.SetData(data)
	assert.Equal(t, data, rh.GetData())
	assert.Equal(t, float32(55.0), rh.GetComplianceScore())
}

func TestGetResults(t *testing.T) {
	rh := makeResultsHandler(80.0, 60.0)
	results := rh.GetResults()
	assert.NotNil(t, results)
}

func TestToJson(t *testing.T) {
	rh := makeResultsHandler(75.0, 50.0)
	data, err := rh.ToJson()
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	// verify it is valid JSON
	var out map[string]interface{}
	assert.NoError(t, json.Unmarshal(data, &out))
}

func TestGetComplianceScoreAndRiskScoreAreIndependent(t *testing.T) {
	rh := makeResultsHandler(80.0, 40.0)
	assert.Equal(t, float32(80.0), rh.GetComplianceScore())
	assert.Equal(t, float32(40.0), rh.GetRiskScore())
	assert.NotEqual(t, rh.GetComplianceScore(), rh.GetRiskScore())
}
