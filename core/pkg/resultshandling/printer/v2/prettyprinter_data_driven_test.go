package printer

import (
	"fmt"
	"os"
	"testing"

	"github.com/anchore/grype/grype/match"
	grypepkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingMainPrinter struct {
	imageSummary  *imageprinter.ImageScanSummary
	nextStepsCall int
}

func (r *recordingMainPrinter) PrintConfigurationsScanning(*reportsummary.SummaryDetails, [][]string, []reporthandling.IResource) {
}

func (r *recordingMainPrinter) PrintImageScanning(summary *imageprinter.ImageScanSummary) {
	r.imageSummary = summary
}

func (r *recordingMainPrinter) PrintNextSteps() {
	r.nextStepsCall++
}

func newDataDrivenPrettyPrinter(t *testing.T) (*PrettyPrinter, func() string) {
	t.Helper()

	file, err := os.CreateTemp(t.TempDir(), "pretty-printer-*.txt")
	require.NoError(t, err)
	pp := &PrettyPrinter{writer: file}
	return pp, func() string {
		require.NoError(t, file.Close())
		contents, err := os.ReadFile(file.Name())
		require.NoError(t, err)
		return string(contents)
	}
}

func TestSetMainPrinterSelectsScanSpecificImplementation(t *testing.T) {
	tests := []struct {
		name     string
		scanType cautils.ScanTypes
		wantType string
	}{
		{name: "cluster", scanType: cautils.ScanTypeCluster, wantType: "*prettyprinter.ClusterPrinter"},
		{name: "repository", scanType: cautils.ScanTypeRepo, wantType: "*prettyprinter.RepoPrinter"},
		{name: "image", scanType: cautils.ScanTypeImage, wantType: "*prettyprinter.ImagePrinter"},
		{name: "workload", scanType: cautils.ScanTypeWorkload, wantType: "*prettyprinter.WorkloadPrinter"},
		{name: "framework fallback", scanType: cautils.ScanTypeFramework, wantType: "*prettyprinter.SummaryPrinter"},
		{name: "unknown fallback", scanType: cautils.ScanTypes("unknown"), wantType: "*prettyprinter.SummaryPrinter"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pp, read := newDataDrivenPrettyPrinter(t)
			pp.scanType = test.scanType
			pp.inputPatterns = []string{"manifests/*.yaml"}
			pp.SetMainPrinter()

			assert.Equal(t, test.wantType, fmt.Sprintf("%T", pp.mainPrinter))
			_ = read()
		})
	}
}

func TestPrintHeaderRendersScanContext(t *testing.T) {
	tests := []struct {
		name       string
		scanType   cautils.ScanTypes
		configure  func(*PrettyPrinter, *cautils.OPASessionObj)
		wantText   []string
		rejectText string
	}{
		{
			name: "cluster", scanType: cautils.ScanTypeCluster,
			configure: func(pp *PrettyPrinter, _ *cautils.OPASessionObj) { pp.clusterName = "production" },
			wantText:  []string{"Security posture overview for cluster", "production", "detect drift"},
		},
		{
			name: "repository", scanType: cautils.ScanTypeRepo,
			configure: func(pp *PrettyPrinter, _ *cautils.OPASessionObj) {
				pp.inputPatterns = []string{"deploy/*.yaml", "charts/app"}
			},
			wantText: []string{"Security posture overview for repo", "deploy/*.yaml, charts/app"},
		},
		{
			name: "namespaced workload", scanType: cautils.ScanTypeWorkload,
			configure: func(_ *PrettyPrinter, session *cautils.OPASessionObj) {
				session.SingleResourceScan = workloadinterface.NewWorkloadObj(map[string]any{
					"apiVersion": "apps/v1", "kind": "Deployment",
					"metadata": map[string]any{"name": "checkout", "namespace": "shop"},
				})
			},
			wantText: []string{"Workload security posture overview", "Namespace", "shop", "Deployment", "checkout"},
		},
		{
			name: "control has no overview header", scanType: cautils.ScanTypeControl,
			wantText: []string{}, rejectText: "Security posture overview",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pp, read := newDataDrivenPrettyPrinter(t)
			pp.scanType = test.scanType
			session := &cautils.OPASessionObj{}
			if test.configure != nil {
				test.configure(pp, session)
			}

			pp.printHeader(session)
			output := read()
			for _, expected := range test.wantText {
				assert.Contains(t, output, expected)
			}
			if test.rejectText != "" {
				assert.NotContains(t, output, test.rejectText)
			}
		})
	}
}

func TestImageSummaryAndDelegation(t *testing.T) {
	imageData := cautils.ImageScanData{
		Image: "test-image:latest",
		Matches: match.NewMatches(match.Match{
			Package: grypepkg.Package{ID: "pkg-1", Name: "openssl", Version: "3.0.0"},
			Vulnerability: vulnerability.Vulnerability{
				Metadata: &vulnerability.Metadata{ID: "CVE-2026-0001", Severity: "High"},
				Fix:      vulnerability.Fix{Versions: []string{"3.0.1"}, State: "Fixed"},
			},
		}),
	}
	tests := []struct {
		name       string
		input      []cautils.ImageScanData
		wantImages []string
		wantCVEs   int
	}{
		{name: "empty", input: nil, wantImages: nil, wantCVEs: 0},
		{name: "single image", input: []cautils.ImageScanData{imageData}, wantImages: []string{"test-image:latest"}, wantCVEs: 1},
		{name: "duplicate image is de-duplicated", input: []cautils.ImageScanData{imageData, imageData}, wantImages: []string{"test-image:latest"}, wantCVEs: 2},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := &recordingMainPrinter{}
			pp := &PrettyPrinter{mainPrinter: recorder}

			pp.PrintImageScan(test.input)
			require.NotNil(t, recorder.imageSummary)
			assert.Equal(t, test.wantImages, recorder.imageSummary.Images)
			assert.Len(t, recorder.imageSummary.CVEs, test.wantCVEs)
		})
	}

	recorder := &recordingMainPrinter{}
	pp := &PrettyPrinter{mainPrinter: recorder}
	pp.PrintNextSteps()
	assert.Equal(t, 1, recorder.nextStepsCall)
}

func TestControlTitleAndSummaryDataDriven(t *testing.T) {
	tests := []struct {
		name       string
		status     apis.ScanningStatus
		subStatus  apis.ScanningSubStatus
		info       string
		wantText   []string
		rejectText []string
	}{
		{
			name: "passed control", status: apis.StatusPassed,
			wantText:   []string{"[control: Privileged containers", "passed", "Description: Containers must not run privileged", "Passed:0", "Total:0"},
			rejectText: []string{"Remediation:", "Reason:"},
		},
		{
			name: "skipped control with reason", status: apis.StatusSkipped, subStatus: apis.SubStatusNotEvaluated,
			info:       "required resource was unavailable",
			wantText:   []string{"action required", "notEvaluated", "Reason: required resource was unavailable"},
			rejectText: []string{"Remediation:"},
		},
		{
			name: "failed control includes remediation", status: apis.StatusFailed,
			wantText: []string{"failed", "Remediation: Set privileged to false", "Failed:0"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pp, read := newDataDrivenPrettyPrinter(t)
			control := &reportsummary.ControlSummary{
				ControlID: "C-0057", Name: "Privileged containers",
				Description: "Containers must not run privileged", Remediation: "Set privileged to false",
			}
			control.SetStatus(&apis.StatusInfo{InnerStatus: test.status, SubStatus: test.subStatus, InnerInfo: test.info})

			pp.printTitle(control)
			pp.printSummary(control)
			output := read()
			for _, expected := range test.wantText {
				assert.Contains(t, output, expected)
			}
			for _, rejected := range test.rejectText {
				assert.NotContains(t, output, rejected)
			}
		})
	}
}
