package telemetry

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// MeterName is the instrumentation scope reported on exported metrics.
const MeterName = "github.com/kubescape/kubescape/v4/core/pkg/telemetry"

// TracerName is deliberately empty: every existing span in the scan pipeline is
// created with otel.Tracer(""), and new spans have to use the same scope to end
// up in the same trace rather than a second one.
const TracerName = ""

// Instrument names keep the kubescape_ prefix and underscore separators already
// used by core/metrics, so a collector scraping both sees one coherent
// namespace rather than two conventions.
const (
	metricScanDuration      = "kubescape_scan_duration_seconds"
	metricScanResources     = "kubescape_scan_resources_total"
	metricControlsEvaluated = "kubescape_scan_controls_evaluated_total"
	metricControls          = "kubescape_scan_controls_total"
	metricComplianceScore   = "kubescape_scan_compliance_score"
	metricImageVulns        = "kubescape_scan_image_vulnerabilities_total"
)

const (
	attrTarget   = "kubescape.scan.target"
	attrKind     = "k8s.resource.kind"
	attrStatus   = "kubescape.control.status"
	attrSeverity = "kubescape.severity"
	attrImage    = "kubescape.image"
	attrFixable  = "kubescape.vulnerability.fixable"

	unknownValue = "unknown"
)

// ControlOutcome is one evaluated control reduced to the two dimensions the
// exported counters break down by.
type ControlOutcome struct {
	Severity string
	Status   string
}

// ImageOutcome carries the vulnerability counts of a single scanned image.
type ImageOutcome struct {
	Image string
	// Fixable and total counts are keyed by severity so a collector can chart
	// either without a second instrument.
	BySeverity        map[string]int64
	FixableBySeverity map[string]int64
}

// ScanOutcome is the complete set of scan-level measurements recorded once per
// scan. It intentionally holds plain values rather than report types so the
// recording path stays independent of the reporting schema.
type ScanOutcome struct {
	Target          string
	Duration        time.Duration
	ComplianceScore float64
	Controls        []ControlOutcome
	ResourcesByKind map[string]int64
	Images          []ImageOutcome

	// HasComplianceScore separates "scored zero" from "no posture score at
	// all", which is the case for a pure image scan.
	HasComplianceScore bool
}

type scanInstruments struct {
	duration          metric.Float64Histogram
	resources         metric.Int64Counter
	controlsEvaluated metric.Int64Counter
	controls          metric.Int64Counter
	complianceScore   metric.Float64Gauge
	imageVulns        metric.Int64Counter
}

var (
	instrumentsMu sync.RWMutex
	instruments   *scanInstruments
)

// initScanInstruments builds the instruments against the meter provider that is
// current at call time. Setup calls it after installing the SDK provider.
func initScanInstruments() {
	meter := otel.GetMeterProvider().Meter(MeterName)

	built := &scanInstruments{}
	var err error

	if built.duration, err = meter.Float64Histogram(
		metricScanDuration,
		metric.WithUnit("s"),
		metric.WithDescription("Wall-clock duration of a Kubescape scan"),
	); err != nil {
		logger.L().Debug("failed to register instrument", helpers.String("name", metricScanDuration), helpers.Error(err))
	}

	if built.resources, err = meter.Int64Counter(
		metricScanResources,
		metric.WithDescription("Resources collected by a Kubescape scan, by kind"),
	); err != nil {
		logger.L().Debug("failed to register instrument", helpers.String("name", metricScanResources), helpers.Error(err))
	}

	if built.controlsEvaluated, err = meter.Int64Counter(
		metricControlsEvaluated,
		metric.WithDescription("Controls evaluated by a Kubescape scan"),
	); err != nil {
		logger.L().Debug("failed to register instrument", helpers.String("name", metricControlsEvaluated), helpers.Error(err))
	}

	if built.controls, err = meter.Int64Counter(
		metricControls,
		metric.WithDescription("Controls evaluated by a Kubescape scan, by status and severity"),
	); err != nil {
		logger.L().Debug("failed to register instrument", helpers.String("name", metricControls), helpers.Error(err))
	}

	if built.complianceScore, err = meter.Float64Gauge(
		metricComplianceScore,
		metric.WithUnit("%"),
		metric.WithDescription("Compliance score of a Kubescape scan"),
	); err != nil {
		logger.L().Debug("failed to register instrument", helpers.String("name", metricComplianceScore), helpers.Error(err))
	}

	if built.imageVulns, err = meter.Int64Counter(
		metricImageVulns,
		metric.WithDescription("Vulnerabilities found in scanned images, by severity and fixability"),
	); err != nil {
		logger.L().Debug("failed to register instrument", helpers.String("name", metricImageVulns), helpers.Error(err))
	}

	instrumentsMu.Lock()
	instruments = built
	instrumentsMu.Unlock()
}

// resetScanInstruments drops the instruments when the providers are torn down,
// so a later RecordScan does not write into an exporter that has shut down.
func resetScanInstruments() {
	instrumentsMu.Lock()
	instruments = nil
	instrumentsMu.Unlock()
}

// RecordScan exports one scan's measurements. It is a no-op when telemetry was
// never enabled, which keeps the call site free of feature checks.
func RecordScan(ctx context.Context, outcome ScanOutcome) {
	instrumentsMu.RLock()
	active := instruments
	instrumentsMu.RUnlock()
	if active == nil {
		return
	}

	target := normalize(outcome.Target)
	targetAttr := metric.WithAttributes(attribute.String(attrTarget, target))

	if active.duration != nil && outcome.Duration > 0 {
		active.duration.Record(ctx, outcome.Duration.Seconds(), targetAttr)
	}

	if active.complianceScore != nil && outcome.HasComplianceScore {
		active.complianceScore.Record(ctx, outcome.ComplianceScore, targetAttr)
	}

	if active.resources != nil {
		for kind, count := range outcome.ResourcesByKind {
			if count <= 0 {
				continue
			}
			active.resources.Add(ctx, count, metric.WithAttributes(
				attribute.String(attrTarget, target),
				attribute.String(attrKind, normalize(kind)),
			))
		}
	}

	if len(outcome.Controls) > 0 {
		if active.controlsEvaluated != nil {
			active.controlsEvaluated.Add(ctx, int64(len(outcome.Controls)), targetAttr)
		}
		if active.controls != nil {
			for key, count := range aggregateControls(outcome.Controls) {
				active.controls.Add(ctx, count, metric.WithAttributes(
					attribute.String(attrTarget, target),
					attribute.String(attrStatus, key.status),
					attribute.String(attrSeverity, key.severity),
				))
			}
		}
	}

	if active.imageVulns != nil {
		recordImages(ctx, active.imageVulns, outcome.Images)
	}
}

type controlKey struct {
	status   string
	severity string
}

func aggregateControls(controls []ControlOutcome) map[controlKey]int64 {
	counts := make(map[controlKey]int64, len(controls))
	for _, control := range controls {
		counts[controlKey{
			status:   normalize(control.Status),
			severity: normalize(control.Severity),
		}]++
	}
	return counts
}

// recordImages splits each severity's total into its fixable and non-fixable
// parts. The two series have to be disjoint: if the fixable=false series
// carried the total instead, summing over the fixable dimension would count
// every fixable vulnerability twice.
func recordImages(ctx context.Context, counter metric.Int64Counter, images []ImageOutcome) {
	for _, image := range images {
		name := normalize(image.Image)

		for severity, total := range image.BySeverity {
			fixable := image.FixableBySeverity[severity]
			if fixable > total {
				// Fixable is a subset of the total by construction; clamp
				// rather than emit a negative delta if a caller disagrees.
				fixable = total
			}
			addImageCount(ctx, counter, name, severity, fixable, true)
			addImageCount(ctx, counter, name, severity, total-fixable, false)
		}

		// A severity that only ever appeared as fixable would otherwise be
		// dropped along with the total it was never counted in.
		for severity, fixable := range image.FixableBySeverity {
			if _, counted := image.BySeverity[severity]; counted {
				continue
			}
			addImageCount(ctx, counter, name, severity, fixable, true)
		}
	}
}

func addImageCount(ctx context.Context, counter metric.Int64Counter, image, severity string, count int64, fixable bool) {
	if count <= 0 {
		return
	}
	counter.Add(ctx, count, metric.WithAttributes(
		attribute.String(attrImage, image),
		attribute.String(attrSeverity, normalize(severity)),
		attribute.Bool(attrFixable, fixable),
	))
}

// normalize keeps attribute cardinality predictable: values are lowercased and
// an empty value becomes an explicit "unknown" rather than a blank label.
func normalize(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return unknownValue
	}
	return value
}
