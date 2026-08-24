package resultshandling

import (
	"context"
	"testing"

	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/telemetry"
	"github.com/kubescape/kubescape/v4/core/pkg/telemetry/telemetrytest"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func startOTLPCollector(t *testing.T) (*telemetrytest.Collector, string) {
	t.Helper()

	collector, err := telemetrytest.Start()
	require.NoError(t, err)
	t.Cleanup(collector.Close)

	return collector, collector.Endpoint()
}

// stubPrinter satisfies printer.IPrinter without writing anything.
type stubPrinter struct{}

func (stubPrinter) PrintNextSteps() {}
func (stubPrinter) ActionPrint(context.Context, *cautils.OPASessionObj, []cautils.ImageScanData) error {
	return nil
}
func (stubPrinter) SetWriter(context.Context, string) error { return nil }
func (stubPrinter) Score(float32)                           {}

func handlerWithImageFindings(t *testing.T) *ResultsHandler {
	t.Helper()

	failed := reportsummary.ControlSummary{ControlID: "C-0001", ScoreFactor: 7}
	failed.StatusInfo = apis.StatusInfo{InnerStatus: apis.StatusFailed}

	session := &cautils.OPASessionObj{
		Report: &reporthandlingv2.PostureReport{},
		AllResources: map[string]workloadinterface.IMetadata{
			"a": newWorkload(t, "Deployment", "api"),
		},
	}
	session.Report.SummaryDetails.ComplianceScore = 64
	session.Report.SummaryDetails.Controls = map[string]reportsummary.ControlSummary{"C-0001": failed}

	handler := NewResultsHandler(nil, nil, stubPrinter{})
	handler.SetData(session)
	handler.ImageScanData = []cautils.ImageScanData{{
		Image: "nginx:1.25",
		Matches: newMatches(t,
			newMatch("CVE-1", "Critical", vulnerability.FixStateFixed),
			newMatch("CVE-2", "Critical", vulnerability.FixStateNotFixed),
		),
	}}

	return handler
}

// TestHandleResultsExportsToCollector covers the wiring end to end: the
// reporting span is created inside HandleResults, and the image vulnerability
// counters reach a collector rather than only being built in memory.
func TestHandleResultsExportsToCollector(t *testing.T) {
	collector, endpoint := startOTLPCollector(t)

	cfg, err := telemetry.ResolveConfig(endpoint, "v3.1.0")
	require.NoError(t, err)

	shutdown, err := telemetry.Setup(context.Background(), cfg)
	require.NoError(t, err)

	handler := handlerWithImageFindings(t)
	require.NoError(t, handler.HandleResults(context.Background(), &cautils.ScanInfo{ScanType: cautils.ScanTypeCluster}))
	require.NoError(t, shutdown(context.Background()))

	assert.Contains(t, collector.SpanNames(), "reporting")

	assert.Equal(t, int64(2), collector.SumPoints("kubescape_scan_image_vulnerabilities_total", map[string]string{
		"kubescape.image":    "nginx:1.25",
		"kubescape.severity": "critical",
	}))
	assert.Equal(t, int64(1), collector.SumPoints("kubescape_scan_controls_total", map[string]string{
		"kubescape.control.status": string(apis.StatusFailed),
		"kubescape.severity":       "high",
	}))
	assert.Equal(t, int64(1), collector.SumPoints("kubescape_scan_resources_total", map[string]string{
		"k8s.resource.kind": "deployment",
	}))
}

// TestHandleResultsRedactsImagesForHiddenScans is the same path with --hide, so
// the redaction is verified where it matters: on the wire.
func TestHandleResultsRedactsImagesForHiddenScans(t *testing.T) {
	collector, endpoint := startOTLPCollector(t)

	cfg, err := telemetry.ResolveConfig(endpoint, "v3.1.0")
	require.NoError(t, err)
	cfg.Redact = true

	shutdown, err := telemetry.Setup(context.Background(), cfg)
	require.NoError(t, err)

	handler := handlerWithImageFindings(t)
	require.NoError(t, handler.HandleResults(context.Background(), &cautils.ScanInfo{
		ScanType: cautils.ScanTypeCluster,
		Hide:     true,
	}))
	require.NoError(t, shutdown(context.Background()))

	assert.Zero(t, collector.SumPoints("kubescape_scan_image_vulnerabilities_total", map[string]string{
		"kubescape.image": "nginx:1.25",
	}))
	assert.Equal(t, int64(2), collector.SumPoints("kubescape_scan_image_vulnerabilities_total", map[string]string{
		"kubescape.severity": "critical",
	}))
}

// TestHandleResultsExportsNothingWhenDisabled is the default path every scan
// takes today.
func TestHandleResultsExportsNothingWhenDisabled(t *testing.T) {
	collector, _ := startOTLPCollector(t)

	require.False(t, telemetry.Active())

	handler := handlerWithImageFindings(t)
	require.NoError(t, handler.HandleResults(context.Background(), &cautils.ScanInfo{ScanType: cautils.ScanTypeCluster}))

	assert.Empty(t, collector.SpanNames())
	assert.False(t, collector.HasMetric("kubescape_scan_image_vulnerabilities_total"))
}
