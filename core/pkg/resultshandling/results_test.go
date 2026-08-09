package resultshandling

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	printerv2 "github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	ActionPrintErr   error
}

func (sp *SpyPrinter) SetWriter(_ context.Context, _ string) {}
func (sp *SpyPrinter) PrintNextSteps()                       {}
func (sp *SpyPrinter) ActionPrint(_ context.Context, _ *cautils.OPASessionObj, _ []cautils.ImageScanData) error {
	sp.ActionPrintCalls += 1
	return sp.ActionPrintErr
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

// TestResultsHandlerHandleResultsImageScanNilScanData reproduces issue #2430:
// image scans construct the handler with a nil ScanData (only ImageScanData is
// set), so HandleResults must not dereference ScanData. Before the fix this
// panicked with a nil pointer dereference in the VAP-reconcile block.
func TestResultsHandlerHandleResultsImageScanNilScanData(t *testing.T) {
	uiPrinter := &SpyPrinter{}
	outputPrinter := &SpyPrinter{}

	// Mirror core.ScanImage: nil reporter, nil ScanData, only ImageScanData.
	rh := NewResultsHandler(nil, []printer.IPrinter{outputPrinter}, uiPrinter)
	rh.ImageScanData = []cautils.ImageScanData{{}}

	assert.Nil(t, rh.ScanData)

	var err error
	assert.NotPanics(t, func() {
		err = rh.HandleResults(context.Background(), &cautils.ScanInfo{})
	})
	assert.NoError(t, err)

	// Results are still printed even though ScanData is nil...
	assert.Equal(t, 1, uiPrinter.ActionPrintCalls)
	assert.Equal(t, 1, outputPrinter.ActionPrintCalls)
	// ...but the compliance score is skipped, as it requires ScanData.
	assert.Equal(t, 0, outputPrinter.ScoreCalls)
}

func TestResultsHandlerHandleResultsReturnsPrinterErrors(t *testing.T) {
	uiErr := errors.New("ui print failed")
	outputErr := errors.New("output print failed")
	uiPrinter := &SpyPrinter{ActionPrintErr: uiErr}
	outputPrinter := &SpyPrinter{ActionPrintErr: outputErr}
	rh := NewResultsHandler(nil, []printer.IPrinter{outputPrinter}, uiPrinter)
	rh.SetData(cautils.NewOPASessionObjMock())

	err := rh.HandleResults(context.Background(), &cautils.ScanInfo{})

	require.Error(t, err)
	assert.ErrorIs(t, err, uiErr)
	assert.ErrorIs(t, err, outputErr)
	assert.Equal(t, 1, uiPrinter.ActionPrintCalls)
	assert.Equal(t, 1, outputPrinter.ActionPrintCalls)
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
			name:      "junit format for image scan should not return error",
			scanType:  cautils.ScanTypeImage,
			format:    printer.JunitResultFormat,
			expectErr: nil,
		},
		{
			name:      "pretty format for image scan should not return error",
			scanType:  cautils.ScanTypeImage,
			format:    printer.PrettyFormat,
			expectErr: nil,
		},
		{
			name:      "html format for image scan should not return error",
			scanType:  cautils.ScanTypeImage,
			format:    printer.HtmlFormat,
			expectErr: nil,
		},
		{
			name:      "prometheus format for image scan should not return error",
			scanType:  cautils.ScanTypeImage,
			format:    printer.PrometheusFormat,
			expectErr: nil,
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
			name:        "gitlab-sast format for cluster context should return error",
			scanContext: cautils.ContextCluster,
			format:      printer.GitLabSASTFormat,
			expectErr:   errors.New("format \"gitlab-sast\" is only supported when scanning local files"),
		},
		{
			name:        "gitlab-sast format for local dir context should not return error",
			scanContext: cautils.ContextDir,
			format:      printer.GitLabSASTFormat,
			expectErr:   nil,
		},
		{
			name:        "gitlab-sast format for local file context should not return error",
			scanContext: cautils.ContextFile,
			format:      printer.GitLabSASTFormat,
			expectErr:   nil,
		},
		{
			name:        "gitlab-sast format for local git context should not return error",
			scanContext: cautils.ContextGitLocal,
			format:      printer.GitLabSASTFormat,
			expectErr:   nil,
		},
		{
			name:      "gitlab-sast format for image scan should not return error",
			scanType:  cautils.ScanTypeImage,
			format:    printer.GitLabSASTFormat,
			expectErr: nil,
		},
		{
			name:      "pdf format for image scan should not return error",
			scanType:  cautils.ScanTypeImage,
			format:    printer.PdfFormat,
			expectErr: nil,
		},
		{
			name:      "csv format for image scan should return error",
			scanType:  cautils.ScanTypeImage,
			format:    printer.CsvFormat,
			expectErr: errors.New("format \"csv\" is not supported for image scanning"),
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
			name:     "GitLab SAST printer",
			format:   "gitlab-sast",
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
	var out map[string]any
	assert.NoError(t, json.Unmarshal(data, &out))
}

// requireJSONSubset verifies that every value in the legacy JSON remains at
// the same path, while allowing the enriched output to add new object fields.
func requireJSONSubset(t *testing.T, want, got any, path string) {
	t.Helper()
	switch want := want.(type) {
	case map[string]any:
		gotMap, ok := got.(map[string]any)
		require.Truef(t, ok, "%s type = %T; want object", path, got)
		for key, wantValue := range want {
			gotValue, exists := gotMap[key]
			require.Truef(t, exists, "legacy JSON path %s.%s disappeared", path, key)
			requireJSONSubset(t, wantValue, gotValue, path+"."+key)
		}
	case []any:
		gotSlice, ok := got.([]any)
		require.Truef(t, ok, "%s type = %T; want array", path, got)
		require.Len(t, gotSlice, len(want), "%s length changed", path)
		for i := range want {
			requireJSONSubset(t, want[i], gotSlice[i], fmt.Sprintf("%s[%d]", path, i))
		}
	default:
		assert.Equalf(t, want, got, "legacy JSON value at %s changed", path)
	}
}

func asLegacyPostureReport(report *reporthandlingv2.PostureReport) *reporthandlingv2.PostureReport {
	return report
}

func TestResultsHandlerToJSONPreservesLegacyFieldsAndAddsEnrichment(t *testing.T) {
	const controlID = "C-ENRICHED"
	resource := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "app",
			"namespace": "tenant-a",
			"labels": map[string]any{
				"team":    "platform",
				"ignored": "not-copied",
			},
		},
	})
	resourceID := resource.GetID()
	scanData := &cautils.OPASessionObj{
		Report: &reporthandlingv2.PostureReport{
			ReportGenerationTime: time.Date(2026, time.August, 9, 1, 2, 3, 456789123, time.UTC),
			SummaryDetails: reportsummary.SummaryDetails{
				Controls: reportsummary.ControlSummaries{
					controlID: {ControlID: controlID, Name: "enriched control", ScoreFactor: 7},
				},
			},
		},
		Metadata: &reporthandlingv2.Metadata{},
		AllResources: map[string]workloadinterface.IMetadata{
			resourceID: resource,
		},
		ResourcesResult: map[string]resourcesresults.Result{
			resourceID: {
				ResourceID: resourceID,
				RawResource: &reporthandling.Resource{
					ResourceID: resourceID,
					Object:     map[string]any{"compatibilityMarker": "preserved"},
				},
				AssociatedControls: []resourcesresults.ResourceAssociatedControl{
					{ControlID: controlID, Name: "enriched control"},
				},
			},
		},
		LabelsToCopy: []string{"team"},
		ScanCoverage: cautils.ScanCoverage{
			PartialGVRPulls: []cautils.PartialGVRPull{
				{GVR: "/v1/pods", Selector: "metadata.namespace=tenant-b", Error: "forbidden"},
			},
			CoverageScore: 98,
			Degraded:      true,
		},
		OmitRawResources: true,
	}
	rh := NewResultsHandler(&DummyReporter{}, nil, &SpyPrinter{})
	rh.SetData(scanData)

	legacyData, err := json.Marshal(printerv2.FinalizeResults(scanData))
	require.NoError(t, err)
	var legacyOutput map[string]any
	require.NoError(t, json.Unmarshal(legacyData, &legacyOutput))

	data, err := rh.ToJson()
	require.NoError(t, err)
	var output map[string]any
	require.NoError(t, json.Unmarshal(data, &output))
	assert.Contains(t, output, "resourceLabels")
	assert.Contains(t, output, "scanCoverage")
	summary, ok := output["summaryDetails"].(map[string]any)
	require.True(t, ok)
	controls, ok := summary["controls"].(map[string]any)
	require.True(t, ok)
	control, ok := controls[controlID].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "High", control["severity"])
	results, ok := output["results"].([]any)
	require.True(t, ok)
	require.Len(t, results, 1)
	result, ok := results[0].(map[string]any)
	require.True(t, ok)
	resultControls, ok := result["controls"].([]any)
	require.True(t, ok)
	require.Len(t, resultControls, 1)
	resultControl, ok := resultControls[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "High", resultControl["severity"])
	labels, ok := output["resourceLabels"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "platform", labels[resourceID].(map[string]any)["team"])
	coverage, ok := output["scanCoverage"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, true, coverage["degraded"])

	// ToJson historically marshaled FinalizeResults directly. All of that JSON
	// must remain intact; the new fields are additive only.
	for _, key := range []string{"reportGUID", "jobID", "paginationInfo", "customerGUIDGenerated"} {
		require.Contains(t, legacyOutput, key)
	}
	requireJSONSubset(t, legacyOutput, output, "$")

	// The legacy typed accessor remains source-compatible and retains its
	// established opa-utils return type.
	legacy := asLegacyPostureReport(rh.GetResults())
	require.NotNil(t, legacy)
	assert.Equal(t, float32(7), legacy.SummaryDetails.Controls[controlID].ScoreFactor)
}

func TestGetComplianceScoreAndRiskScoreAreIndependent(t *testing.T) {
	rh := makeResultsHandler(80.0, 40.0)
	assert.Equal(t, float32(80.0), rh.GetComplianceScore())
	assert.Equal(t, float32(40.0), rh.GetRiskScore())
	assert.NotEqual(t, rh.GetComplianceScore(), rh.GetRiskScore())
}

// TestValidatePrinter_ImageFormatsInvariant pins the invariant itself: every
// format in printer.ImageFormats must be accepted for image scans, and every
// format in printer.AllFormats that is NOT in printer.ImageFormats (e.g. csv)
// must be rejected. This is what stops a future format from silently
// inheriting image-scan support just by being added to AllFormats (#2782 review).
func TestValidatePrinter_ImageFormatsInvariant(t *testing.T) {
	for _, format := range printer.ImageFormats {
		t.Run("accepted: "+format, func(t *testing.T) {
			_, err := ValidatePrinter(cautils.ScanTypeImage, cautils.ScanningContext(""), format)
			assert.NoError(t, err)
		})
	}

	for _, format := range printer.AllFormats {
		if slices.Contains(printer.ImageFormats, format) {
			continue
		}
		t.Run("rejected: "+format, func(t *testing.T) {
			_, err := ValidatePrinter(cautils.ScanTypeImage, cautils.ScanningContext(""), format)
			assert.Error(t, err)
		})
	}
}
