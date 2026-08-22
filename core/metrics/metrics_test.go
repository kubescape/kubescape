package metrics

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func resetMetricsForTest(t *testing.T) {
	t.Helper()
	ResetForTest(t)
}

func setMeterProviderForTest(t *testing.T, provider *sdkmetric.MeterProvider) {
	t.Helper()

	previousProvider := otel.GetMeterProvider()
	otel.SetMeterProvider(provider)

	t.Cleanup(func() {
		require.NoError(t, provider.Shutdown(context.Background()))
		otel.SetMeterProvider(previousProvider)
	})
}

func TestInit(t *testing.T) {
	resetMetricsForTest(t)

	// Init should be safe to call multiple times thanks to sync.Once.
	assert.NotPanics(t, func() { Init() })
	require.NotNil(t, kubernetesResourcesCount)
	require.NotNil(t, workerNodesCount)

	assert.NotPanics(t, func() { Init() })
	require.NotNil(t, kubernetesResourcesCount)
	require.NotNil(t, workerNodesCount)
}

func TestUpdatesReportLatestValues(t *testing.T) {
	resetMetricsForTest(t)
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	setMeterProviderForTest(t, provider)

	Init()
	UpdateKubernetesResourcesCount(context.Background(), 3)
	UpdateWorkerNodesCount(context.Background(), 2)

	got := collectMetricSums(t, reader)
	assert.Equal(t, int64(3), got["kubescape_kubernetes_resources_count"])
	assert.Equal(t, int64(2), got["kubescape_worker_nodes_count"])

	UpdateKubernetesResourcesCount(context.Background(), 4)
	UpdateWorkerNodesCount(context.Background(), 1)

	got = collectMetricSums(t, reader)

	assert.Equal(t, int64(4), got["kubescape_kubernetes_resources_count"])
	assert.Equal(t, int64(1), got["kubescape_worker_nodes_count"])
}

func TestUpdatesRemainConsistentConcurrently(t *testing.T) {
	resetMetricsForTest(t)
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	setMeterProviderForTest(t, provider)
	Init()

	var wg sync.WaitGroup
	for value := int64(1); value <= 32; value++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			UpdateKubernetesResourcesCount(context.Background(), value)
			UpdateWorkerNodesCount(context.Background(), value)
		}()
	}
	wg.Wait()

	// Make the final observations deterministic after the concurrent updates.
	UpdateKubernetesResourcesCount(context.Background(), 5)
	UpdateWorkerNodesCount(context.Background(), 2)

	got := collectMetricSums(t, reader)
	assert.Equal(t, int64(5), got["kubescape_kubernetes_resources_count"])
	assert.Equal(t, int64(2), got["kubescape_worker_nodes_count"])
}

func TestInitAndUpdatesRemainConsistentConcurrently(t *testing.T) {
	resetMetricsForTest(t)
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	setMeterProviderForTest(t, provider)

	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(started)
		for value := int64(1); value <= 256; value++ {
			UpdateKubernetesResourcesCount(context.Background(), value)
			UpdateWorkerNodesCount(context.Background(), value)
		}
		close(done)
	}()

	<-started
	Init()
	<-done

	// Updates racing with initialization may be no-ops. A final observation
	// after Init must still establish the exact exported values.
	UpdateKubernetesResourcesCount(context.Background(), 5)
	UpdateWorkerNodesCount(context.Background(), 2)

	got := collectMetricSums(t, reader)
	assert.Equal(t, int64(5), got["kubescape_kubernetes_resources_count"])
	assert.Equal(t, int64(2), got["kubescape_worker_nodes_count"])
}

func TestInitOnlyRegistersOnce(t *testing.T) {
	resetMetricsForTest(t)
	firstReader := sdkmetric.NewManualReader()
	firstProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(firstReader))
	setMeterProviderForTest(t, firstProvider)

	Init()

	secondReader := sdkmetric.NewManualReader()
	secondProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(secondReader))
	setMeterProviderForTest(t, secondProvider)

	Init()
	UpdateWorkerNodesCount(context.Background(), 5)

	assert.Equal(t, int64(5), collectMetricSums(t, firstReader)["kubescape_worker_nodes_count"])
	assert.Empty(t, collectMetricSums(t, secondReader))
}

func TestUpdatesBeforeInitAreNoOps(t *testing.T) {
	resetMetricsForTest(t)
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	setMeterProviderForTest(t, provider)

	assert.NotPanics(t, func() {
		UpdateKubernetesResourcesCount(context.Background(), 100)
		UpdateWorkerNodesCount(context.Background(), 100)
	})

	Init()
	UpdateKubernetesResourcesCount(context.Background(), 3)
	UpdateWorkerNodesCount(context.Background(), 2)

	got := collectMetricSums(t, reader)
	assert.Equal(t, int64(3), got["kubescape_kubernetes_resources_count"])
	assert.Equal(t, int64(2), got["kubescape_worker_nodes_count"])
}

func TestUpdateKubernetesResourcesCount_NilCounter(t *testing.T) {
	resetMetricsForTest(t)

	assert.NotPanics(t, func() {
		UpdateKubernetesResourcesCount(context.Background(), 5)
	})
}

func TestUpdateWorkerNodesCount_NilCounter(t *testing.T) {
	resetMetricsForTest(t)

	assert.NotPanics(t, func() {
		UpdateWorkerNodesCount(context.Background(), 3)
	})
}

func TestUpdateKubernetesResourcesCount_AfterInit(t *testing.T) {
	resetMetricsForTest(t)

	Init()
	require.NotNil(t, kubernetesResourcesCount)

	assert.NotPanics(t, func() {
		UpdateKubernetesResourcesCount(context.Background(), 10)
	})
}

func TestUpdateWorkerNodesCount_AfterInit(t *testing.T) {
	resetMetricsForTest(t)

	Init()
	require.NotNil(t, workerNodesCount)

	assert.NotPanics(t, func() {
		UpdateWorkerNodesCount(context.Background(), 4)
	})
}

func collectMetricSums(t *testing.T, reader *sdkmetric.ManualReader) map[string]int64 {
	t.Helper()

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))

	got := map[string]int64{}
	for _, scopeMetric := range rm.ScopeMetrics {
		for _, metric := range scopeMetric.Metrics {
			sum, ok := metric.Data.(metricdata.Sum[int64])
			if !ok || len(sum.DataPoints) == 0 {
				continue
			}
			got[metric.Name] = sum.DataPoints[0].Value
		}
	}
	return got
}
