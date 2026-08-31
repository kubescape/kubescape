package telemetry

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// newTestMeterProvider installs a manually collected meter provider and builds
// the scan instruments against it, mirroring what Setup does with a real one.
func newTestMeterProvider(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()

	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))

	previous := otel.GetMeterProvider()
	otel.SetMeterProvider(provider)
	initScanInstruments()

	t.Cleanup(func() {
		resetScanInstruments()
		otel.SetMeterProvider(previous)
		_ = provider.Shutdown(context.Background())
	})

	return reader
}

func collect(t *testing.T, reader *sdkmetric.ManualReader) map[string]metricdata.Metrics {
	t.Helper()

	var collected metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &collected))

	byName := map[string]metricdata.Metrics{}
	for _, scope := range collected.ScopeMetrics {
		for _, m := range scope.Metrics {
			byName[m.Name] = m
		}
	}
	return byName
}

func sumFor(t *testing.T, m metricdata.Metrics, want map[string]string) int64 {
	t.Helper()

	sum, ok := m.Data.(metricdata.Sum[int64])
	require.True(t, ok, "metric %s is not an int64 sum", m.Name)

	var total int64
	for _, point := range sum.DataPoints {
		matches := true
		for key, value := range want {
			actual, found := point.Attributes.Value(attribute.Key(key))
			if !found || actual.String() != value {
				matches = false
				break
			}
		}
		if matches {
			total += point.Value
		}
	}
	return total
}

func gaugeValueFor(t *testing.T, m metricdata.Metrics, want map[string]string) (int64, bool) {
	t.Helper()

	gauge, ok := m.Data.(metricdata.Gauge[int64])
	require.True(t, ok, "metric %s is not an int64 gauge", m.Name)

	for _, point := range gauge.DataPoints {
		matches := true
		for key, value := range want {
			actual, found := point.Attributes.Value(attribute.Key(key))
			if !found || actual.String() != value {
				matches = false
				break
			}
		}
		if matches {
			return point.Value, true
		}
	}
	return 0, false
}

func TestRecordScanWithoutSetupIsNoop(t *testing.T) {
	resetScanInstruments()

	assert.NotPanics(t, func() {
		RecordScan(context.Background(), ScanOutcome{
			Target:          "cluster",
			Duration:        time.Second,
			Controls:        []ControlOutcome{{Severity: "High", Status: "failed"}},
			ResourcesByKind: map[string]int64{"Deployment": 2},
		})
	})
}

func TestRecordScanExportsScanLevelMetrics(t *testing.T) {
	reader := newTestMeterProvider(t)

	RecordScan(context.Background(), ScanOutcome{
		Target:             "cluster",
		Duration:           1500 * time.Millisecond,
		ComplianceScore:    82.5,
		HasComplianceScore: true,
		Controls: []ControlOutcome{
			{Severity: "High", Status: "failed"},
			{Severity: "High", Status: "failed"},
			{Severity: "Medium", Status: "passed"},
			{Severity: "Low", Status: "skipped"},
		},
		ResourcesByKind: map[string]int64{"Deployment": 3, "Service": 2},
	})

	metrics := collect(t, reader)

	duration, ok := metrics[metricScanDuration]
	require.True(t, ok, "scan duration was not exported")
	histogram, ok := duration.Data.(metricdata.Histogram[float64])
	require.True(t, ok)
	require.Len(t, histogram.DataPoints, 1)
	assert.Equal(t, uint64(1), histogram.DataPoints[0].Count)
	assert.InDelta(t, 1.5, histogram.DataPoints[0].Sum, 0.001)

	score, ok := metrics[metricComplianceScore]
	require.True(t, ok, "compliance score was not exported")
	gauge, ok := score.Data.(metricdata.Gauge[float64])
	require.True(t, ok)
	require.Len(t, gauge.DataPoints, 1)
	assert.InDelta(t, 82.5, gauge.DataPoints[0].Value, 0.001)

	evaluated, ok := metrics[metricControlsEvaluated]
	require.True(t, ok, "controls evaluated was not exported")
	assert.Equal(t, int64(4), sumFor(t, evaluated, map[string]string{attrTarget: "cluster"}))

	controls, ok := metrics[metricControls]
	require.True(t, ok, "controls breakdown was not exported")
	assert.Equal(t, int64(2), sumFor(t, controls, map[string]string{attrStatus: "failed", attrSeverity: "high"}))
	assert.Equal(t, int64(1), sumFor(t, controls, map[string]string{attrStatus: "passed", attrSeverity: "medium"}))
	assert.Equal(t, int64(1), sumFor(t, controls, map[string]string{attrStatus: "skipped", attrSeverity: "low"}))

	resources, ok := metrics[metricScanResources]
	require.True(t, ok, "resource counts were not exported")
	assert.Equal(t, int64(3), sumFor(t, resources, map[string]string{attrKind: "deployment"}))
	assert.Equal(t, int64(2), sumFor(t, resources, map[string]string{attrKind: "service"}))
}

func TestRecordScanExportsImageVulnerabilities(t *testing.T) {
	reader := newTestMeterProvider(t)

	RecordScan(context.Background(), ScanOutcome{
		Target: "image",
		Images: []ImageOutcome{
			{
				Image:             "nginx:1.25",
				BySeverity:        map[string]int64{"Critical": 4, "Low": 9},
				FixableBySeverity: map[string]int64{"Critical": 3},
			},
		},
	})

	metrics := collect(t, reader)
	vulns, ok := metrics[metricImageVulns]
	require.True(t, ok, "image vulnerabilities were not exported")

	// BySeverity is the total and FixableBySeverity a subset of it, so the two
	// exported series must partition that total rather than overlap.
	assert.Equal(t, int64(3), sumFor(t, vulns, map[string]string{attrSeverity: "critical", attrFixable: "true"}))
	assert.Equal(t, int64(1), sumFor(t, vulns, map[string]string{attrSeverity: "critical", attrFixable: "false"}))
	assert.Equal(t, int64(9), sumFor(t, vulns, map[string]string{attrSeverity: "low", attrFixable: "false"}))
	assert.Equal(t, int64(0), sumFor(t, vulns, map[string]string{attrSeverity: "low", attrFixable: "true"}))

	// Summing across the fixable dimension recovers the true totals.
	assert.Equal(t, int64(4), sumFor(t, vulns, map[string]string{attrSeverity: "critical"}))
	assert.Equal(t, int64(13), sumFor(t, vulns, map[string]string{attrImage: "nginx:1.25"}))
}

func TestRecordScanExportsImageVulnDBAge(t *testing.T) {
	reader := newTestMeterProvider(t)
	built := time.Now().Add(-2 * time.Hour).UTC()

	RecordScan(context.Background(), ScanOutcome{
		Target: "image",
		Images: []ImageOutcome{
			{
				Image:             "nginx:1.25",
				BySeverity:        map[string]int64{"Critical": 1},
				FixableBySeverity: map[string]int64{},
				VulnDBBuilt:       built,
				HasVulnDBBuilt:    true,
			},
		},
	})

	dbAge, ok := collect(t, reader)[metricImageVulnDBAge]
	require.True(t, ok, "image vulnerability DB age was not exported")

	age, found := gaugeValueFor(t, dbAge, map[string]string{attrImage: "nginx:1.25"})
	require.True(t, found, "image DB age point was not exported")
	assert.GreaterOrEqual(t, age, int64((2 * time.Hour).Seconds()))
	assert.Less(t, age, int64((2*time.Hour + time.Minute).Seconds()))
}

func TestRecordScanSkipsMissingImageVulnDBAge(t *testing.T) {
	reader := newTestMeterProvider(t)

	RecordScan(context.Background(), ScanOutcome{
		Target: "image",
		Images: []ImageOutcome{{
			Image:             "nginx:1.25",
			BySeverity:        map[string]int64{"High": 1},
			FixableBySeverity: map[string]int64{},
		}},
	})

	metrics := collect(t, reader)
	assert.NotContains(t, metrics, metricImageVulnDBAge)
}

func TestRecordScanClampsFixableAboveTotal(t *testing.T) {
	reader := newTestMeterProvider(t)

	RecordScan(context.Background(), ScanOutcome{
		Target: "image",
		Images: []ImageOutcome{{
			Image:             "nginx:1.25",
			BySeverity:        map[string]int64{"High": 2},
			FixableBySeverity: map[string]int64{"High": 5, "Low": 3},
		}},
	})

	vulns := collect(t, reader)[metricImageVulns]

	// A counter cannot take a negative delta, so an inconsistent subset is
	// clamped instead of underflowing the non-fixable series.
	assert.Equal(t, int64(2), sumFor(t, vulns, map[string]string{attrSeverity: "high", attrFixable: "true"}))
	assert.Equal(t, int64(0), sumFor(t, vulns, map[string]string{attrSeverity: "high", attrFixable: "false"}))
	// A severity seen only as fixable is still reported.
	assert.Equal(t, int64(3), sumFor(t, vulns, map[string]string{attrSeverity: "low", attrFixable: "true"}))
}

func TestRecordScanSkipsAbsentMeasurements(t *testing.T) {
	reader := newTestMeterProvider(t)

	// A scan that produced no posture score, no controls and no resources must
	// not publish zero-valued series that would skew a dashboard.
	RecordScan(context.Background(), ScanOutcome{Target: "image"})

	metrics := collect(t, reader)

	assert.NotContains(t, metrics, metricComplianceScore)
	assert.NotContains(t, metrics, metricControls)
	assert.NotContains(t, metrics, metricControlsEvaluated)
	assert.NotContains(t, metrics, metricScanDuration)
}

func TestRecordScanNormalizesAttributes(t *testing.T) {
	reader := newTestMeterProvider(t)

	RecordScan(context.Background(), ScanOutcome{
		Controls:        []ControlOutcome{{Severity: "", Status: ""}},
		ResourcesByKind: map[string]int64{"": 1, "Deployment": -4},
	})

	metrics := collect(t, reader)

	controls := metrics[metricControls]
	assert.Equal(t, int64(1), sumFor(t, controls, map[string]string{
		attrTarget:   unknownValue,
		attrStatus:   unknownValue,
		attrSeverity: unknownValue,
	}))

	resources := metrics[metricScanResources]
	assert.Equal(t, int64(1), sumFor(t, resources, map[string]string{attrKind: unknownValue}))
	// A negative delta is invalid for a counter, so it is dropped rather than
	// handed to the SDK.
	assert.Equal(t, int64(0), sumFor(t, resources, map[string]string{attrKind: "deployment"}))
}

func TestResetScanInstrumentsStopsRecording(t *testing.T) {
	reader := newTestMeterProvider(t)

	resetScanInstruments()
	RecordScan(context.Background(), ScanOutcome{Target: "cluster", Duration: time.Second})

	assert.NotContains(t, collect(t, reader), metricScanDuration)
}
