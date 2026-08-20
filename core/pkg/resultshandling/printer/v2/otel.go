package printer

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
)

// otelMeterName identifies kubescape's instrumentation scope to consumers of
// the exported metrics (e.g. shown as the "scope" in a Grafana/Prometheus
// OTel view). It intentionally mirrors core/metrics.METER_NAME's module-path
// convention.
const otelMeterName = "github.com/kubescape/kubescape/v4/scan"

var _ printer.IPrinter = &OtelPrinter{}

// OtelPrinter exports scan-level metrics through the OTel metrics API
// (go.opentelemetry.io/otel/metric), alongside the scan-phase spans already
// emitted via otel.Tracer("") throughout core/core/scan.go.
//
// Unlike the file-based printers (Prometheus included), it never writes an
// output file: metrics are pushed to whatever MeterProvider is registered
// globally via otel.SetMeterProvider (see core/pkg/telemetry.Setup, wired
// from --otel-endpoint / OTEL_EXPORTER_OTLP_ENDPOINT in cmd/scan). If no
// MeterProvider was registered because the flag/env var was never set,
// otel.GetMeterProvider() returns the OTel SDK's built-in no-op provider and
// every instrument recorded below becomes a cheap no-op -- this is what
// keeps the "otel" format free of runtime/dependency overhead when it isn't
// requested (see issue #3402 acceptance criteria).
type OtelPrinter struct {
	verboseMode bool
	// createdAt is set when the printer is constructed, which happens early
	// in core.GetOutputPrinters -- i.e. before resource collection starts.
	// ActionPrint (called once, after the full scan) measures elapsed time
	// against this, giving an approximate end-to-end scan duration without
	// needing a dedicated timer threaded through the scan pipeline.
	createdAt time.Time
}

// NewOtelPrinter constructs an OtelPrinter. verboseMode is accepted for
// symmetry with the other v2 printers' constructors; the otel format has no
// verbose/non-verbose distinction today.
func NewOtelPrinter(verboseMode bool) *OtelPrinter {
	return &OtelPrinter{
		verboseMode: verboseMode,
		createdAt:   time.Now(),
	}
}

func (op *OtelPrinter) PrintNextSteps() {}

// SetWriter is a no-op: the otel format exports over OTLP, not to a file.
// An explicit --output is accepted (so it does not break `--format
// otel,json --output report` style multi-format invocations) but ignored.
func (op *OtelPrinter) SetWriter(ctx context.Context, outputFile string) error {
	if outputFile != "" {
		logger.L().Ctx(ctx).Warning("--output is ignored for the \"otel\" format; metrics are exported via OTLP to --otel-endpoint instead of a file")
	}
	return nil
}

// Score is intentionally a no-op. The compliance score is already exported
// as part of ActionPrint's control counters; a separate Score() call (fired
// after ActionPrint, see resultshandling.ResultsHandler.HandleResults) would
// only duplicate it.
func (op *OtelPrinter) Score(score float32) {}

// CloseWriter satisfies the optional errorCloser contract; there is no file
// handle to close.
func (op *OtelPrinter) CloseWriter() error { return nil }

func (op *OtelPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) error {
	meter := otel.Meter(otelMeterName)

	if err := op.recordDuration(ctx, meter); err != nil {
		logger.L().Ctx(ctx).Warning("failed to record otel scan duration", helpers.Error(err))
	}

	switch {
	case opaSessionObj != nil:
		m := &Metrics{}
		m.setComplianceScores(&opaSessionObj.Report.SummaryDetails)

		if err := op.recordResourceCounts(ctx, meter, opaSessionObj.AllResources); err != nil {
			logger.L().Ctx(ctx).Warning("failed to record otel resource counts", helpers.Error(err))
		}
		if err := op.recordControlCounts(ctx, meter, m); err != nil {
			logger.L().Ctx(ctx).Warning("failed to record otel control counts", helpers.Error(err))
		}
	case len(imageScanData) > 0:
		if err := op.recordImageMetrics(ctx, meter, imageScanData); err != nil {
			logger.L().Ctx(ctx).Warning("failed to record otel image metrics", helpers.Error(err))
		}
	default:
		return fmt.Errorf("failed to print results, missing data")
	}

	logger.L().Ctx(ctx).Success("Scan metrics exported via OTel")
	return nil
}

// recordDuration records the approximate scan duration. See createdAt's
// doc comment for what it measures and why.
func (op *OtelPrinter) recordDuration(ctx context.Context, meter metric.Meter) error {
	hist, err := meter.Float64Histogram(
		"kubescape_scan_duration_seconds",
		metric.WithDescription("Approximate wall-clock duration of the scan, from output-printer setup to results printing"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return err
	}
	hist.Record(ctx, time.Since(op.createdAt).Seconds())
	return nil
}

// recordResourceCounts records the number of collected Kubernetes resources,
// broken down by kind (issue #3402: "resource count by kind").
func (op *OtelPrinter) recordResourceCounts(ctx context.Context, meter metric.Meter, resources map[string]workloadinterface.IMetadata) error {
	gauge, err := meter.Int64Gauge(
		"kubescape_scan_resource_count",
		metric.WithDescription("Number of Kubernetes resources collected for the scan, by kind"),
	)
	if err != nil {
		return err
	}

	byKind := make(map[string]int64, len(resources))
	for _, r := range resources {
		byKind[r.GetKind()]++
	}
	for kind, count := range byKind {
		gauge.Record(ctx, count, metric.WithAttributes(attribute.String("kind", kind)))
	}
	return nil
}

// recordControlCounts records the total number of controls evaluated, and
// resource-level pass/fail counts grouped by control severity (issue #3402:
// "controls evaluated, controls passed/failed by severity").
func (op *OtelPrinter) recordControlCounts(ctx context.Context, meter metric.Meter, m *Metrics) error {
	evaluated, err := meter.Int64Gauge(
		"kubescape_scan_controls_evaluated",
		metric.WithDescription("Total number of controls evaluated by the scan"),
	)
	if err != nil {
		return err
	}
	evaluated.Record(ctx, int64(m.rs.controlsCountPassed+m.rs.controlsCountFailed+m.rs.controlsCountSkipped))

	result, err := meter.Int64Gauge(
		"kubescape_scan_controls_result",
		metric.WithDescription("Control evaluation results (resource-level pass/fail counts), grouped by control severity and status"),
	)
	if err != nil {
		return err
	}

	type tally struct{ passed, failed int64 }
	bySeverity := make(map[string]*tally)
	for i := range m.listControls {
		c := &m.listControls[i]
		t, ok := bySeverity[c.severity]
		if !ok {
			t = &tally{}
			bySeverity[c.severity] = t
		}
		t.passed += int64(c.resourcesCountPassed)
		t.failed += int64(c.resourcesCountFailed)
	}
	for severity, t := range bySeverity {
		result.Record(ctx, t.passed, metric.WithAttributes(attribute.String("severity", severity), attribute.String("status", "passed")))
		result.Record(ctx, t.failed, metric.WithAttributes(attribute.String("severity", severity), attribute.String("status", "failed")))
	}
	return nil
}

// recordImageMetrics records per-image, per-severity CVE counts for an image
// scan, mirroring PrometheusPrinter.generateImagePrometheusFormat (#2782) so
// the two formats stay consistent for image-scan consumers.
func (op *OtelPrinter) recordImageMetrics(ctx context.Context, meter metric.Meter, imageScanData []cautils.ImageScanData) error {
	m := &Metrics{isImageScan: true}
	m.setImageVulnerabilities(imageScanData)

	cve, err := meter.Int64Gauge(
		"kubescape_scan_image_cve_count",
		metric.WithDescription("Number of CVEs found per scanned image, by severity"),
	)
	if err != nil {
		return err
	}
	for _, iv := range m.listImages {
		cve.Record(ctx, int64(iv.cveCount),
			metric.WithAttributes(
				attribute.String("image", iv.image),
				attribute.String("severity", iv.severity),
			),
		)
	}
	return nil
}
