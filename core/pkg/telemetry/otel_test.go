package telemetry

import (
	"context"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/core/pkg/telemetry/telemetrytest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
)

// startFakeCollector runs an OTLP endpoint for the duration of the test.
func startFakeCollector(t *testing.T) (*telemetrytest.Collector, string) {
	t.Helper()

	collector, err := telemetrytest.Start()
	require.NoError(t, err)
	t.Cleanup(collector.Close)

	return collector, collector.Endpoint()
}

func TestSetupDisabledReturnsNoopShutdown(t *testing.T) {
	previousTracerProvider := otel.GetTracerProvider()
	previousMeterProvider := otel.GetMeterProvider()

	shutdown, err := Setup(context.Background(), Config{})

	require.NoError(t, err)
	require.NotNil(t, shutdown)
	assert.NoError(t, shutdown(context.Background()))
	assert.False(t, Active())

	// A disabled config must leave the globals untouched: that is what keeps
	// the default scan path free of SDK cost.
	assert.Same(t, previousTracerProvider, otel.GetTracerProvider())
	assert.Same(t, previousMeterProvider, otel.GetMeterProvider())
}

func TestSetupExportsSpansAndMetrics(t *testing.T) {
	collector, endpoint := startFakeCollector(t)

	cfg, err := ResolveConfig(endpoint, "v3.1.0")
	require.NoError(t, err)

	shutdown, err := Setup(context.Background(), cfg)
	require.NoError(t, err)
	require.True(t, Active())

	ctx, root := otel.Tracer(TracerName).Start(context.Background(), "kubescape.scan")
	for _, phase := range []string{"resources", "opa testing", "reporting"} {
		_, span := otel.Tracer(TracerName).Start(ctx, phase)
		span.End()
	}
	root.End()

	RecordScan(ctx, ScanOutcome{
		Target:             "cluster",
		Duration:           2 * time.Second,
		ComplianceScore:    91,
		HasComplianceScore: true,
		Controls:           []ControlOutcome{{Severity: "high", Status: "failed"}},
		ResourcesByKind:    map[string]int64{"Deployment": 1},
	})

	require.NoError(t, shutdown(context.Background()))
	assert.False(t, Active())

	assert.ElementsMatch(t,
		[]string{"resources", "opa testing", "reporting", "kubescape.scan"},
		collector.SpanNames(),
	)

	exported := collector.MetricNames()
	assert.Contains(t, exported, metricScanDuration)
	assert.Contains(t, exported, metricComplianceScore)
	assert.Contains(t, exported, metricControls)
	assert.Contains(t, exported, metricControlsEvaluated)
	assert.Contains(t, exported, metricScanResources)

	assert.Equal(t, DefaultServiceName, collector.ResourceAttribute("service.name"))
	assert.Equal(t, "v3.1.0", collector.ResourceAttribute("service.version"))
	assert.NotEmpty(t, collector.ResourceAttribute("host.name"))
}

func TestSetupRedactDropsHostAttributes(t *testing.T) {
	collector, endpoint := startFakeCollector(t)

	cfg, err := ResolveConfig(endpoint, "v3.1.0")
	require.NoError(t, err)
	cfg.Redact = true

	shutdown, err := Setup(context.Background(), cfg)
	require.NoError(t, err)

	_, span := otel.Tracer(TracerName).Start(context.Background(), "reporting")
	span.End()
	require.NoError(t, shutdown(context.Background()))

	// --hide/--encrypt anonymize the report; the resource must not name the
	// machine instead.
	assert.Empty(t, collector.ResourceAttribute("host.name"))
	assert.Equal(t, DefaultServiceName, collector.ResourceAttribute("service.name"))
}

func TestSetupIsIdempotentWhileActive(t *testing.T) {
	_, endpoint := startFakeCollector(t)

	cfg, err := ResolveConfig(endpoint, "")
	require.NoError(t, err)

	shutdown, err := Setup(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	installed := otel.GetTracerProvider()

	// A nested scan subcommand must not replace the providers mid-scan.
	nested, err := Setup(context.Background(), cfg)
	require.NoError(t, err)
	require.NoError(t, nested(context.Background()))

	assert.Same(t, installed, otel.GetTracerProvider())
	assert.True(t, Active())
}

func TestShutdownIsBoundedWhenCollectorIsUnreachable(t *testing.T) {
	// Port 1 is reserved and refuses immediately, standing in for a collector
	// that was configured but is not answering.
	cfg, err := ResolveConfig("127.0.0.1:1", "")
	require.NoError(t, err)

	shutdown, err := Setup(context.Background(), cfg)
	require.NoError(t, err)

	_, span := otel.Tracer(TracerName).Start(context.Background(), "reporting")
	span.End()
	RecordScan(context.Background(), ScanOutcome{Target: "cluster", Duration: time.Second})

	start := time.Now()
	err = shutdown(context.Background())
	elapsed := time.Since(start)

	// A misconfigured endpoint must not hold the CLI open past the flush
	// ceiling, and the error is reported rather than swallowed.
	assert.Error(t, err, "an unreachable collector should surface a flush error")
	assert.Less(t, elapsed, shutdownTimeout+time.Second,
		"shutdown must stay within the flush ceiling, took %s", elapsed)
	assert.False(t, Active())
}

func TestShutdownRestoresPreviousProviders(t *testing.T) {
	_, endpoint := startFakeCollector(t)

	previousTracerProvider := otel.GetTracerProvider()
	previousMeterProvider := otel.GetMeterProvider()

	cfg, err := ResolveConfig(endpoint, "")
	require.NoError(t, err)

	shutdown, err := Setup(context.Background(), cfg)
	require.NoError(t, err)
	require.NotSame(t, previousTracerProvider, otel.GetTracerProvider())

	require.NoError(t, shutdown(context.Background()))
	assert.Same(t, previousTracerProvider, otel.GetTracerProvider())
	assert.Same(t, previousMeterProvider, otel.GetMeterProvider())

	// Calling shutdown again must stay safe and keep the globals restored.
	require.NoError(t, shutdown(context.Background()))
	assert.Same(t, previousTracerProvider, otel.GetTracerProvider())
}

func TestShutdownFlushesWithCancelledContext(t *testing.T) {
	collector, endpoint := startFakeCollector(t)

	cfg, err := ResolveConfig(endpoint, "")
	require.NoError(t, err)

	shutdown, err := Setup(context.Background(), cfg)
	require.NoError(t, err)

	_, span := otel.Tracer(TracerName).Start(context.Background(), "reporting")
	span.End()

	// Scans that hit --scan-timeout hand a dead context to the flush; the last
	// batch still has to reach the collector.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	require.NoError(t, shutdown(cancelled))
	assert.Contains(t, collector.SpanNames(), "reporting")
}
