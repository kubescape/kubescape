package metrics

import (
	"context"
	"strings"
	"sync"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

const (
	METER_NAME         = "github.com/kubescape/kubescape/v4"
	METRIC_NAME_PREFIX = "kubescape"
)

var initOnce sync.Once

// Metrics are defined here
var (
	kubernetesResourcesCount metric.Int64UpDownCounter
	workerNodesCount         metric.Int64UpDownCounter

	// Resource collection reports absolute snapshots, while UpDownCounter.Add
	// records changes. Retain the previous snapshots so repeated updates export
	// the latest values without changing the existing instrument contract.
	lastValueMu                  sync.Mutex
	lastKubernetesResourcesCount int64
	lastWorkerNodesCount         int64
)

// Init initializes the metrics
func Init() {
	initOnce.Do(func() {
		meterProvider := otel.GetMeterProvider()
		meter := meterProvider.Meter(METER_NAME)
		metricName := func(name string) string {
			return strings.Join([]string{METRIC_NAME_PREFIX, name}, "_")
		}

		resourcesCounter, err := meter.Int64UpDownCounter(metricName("kubernetes_resources_count"))
		if err != nil {
			logger.L().Error("failed to register instrument", helpers.Error(err))
		}

		workersCounter, err := meter.Int64UpDownCounter(metricName("worker_nodes_count"))
		if err != nil {
			logger.L().Error("failed to register instrument", helpers.Error(err))
		}

		lastValueMu.Lock()
		kubernetesResourcesCount = resourcesCounter
		workerNodesCount = workersCounter
		lastValueMu.Unlock()
	})
}

// UpdateKubernetesResourcesCount updates the kubernetes resources count metric
func UpdateKubernetesResourcesCount(ctx context.Context, value int64) {
	updateCounter(ctx, &kubernetesResourcesCount, &lastKubernetesResourcesCount, value)
}

// UpdateWorkerNodesCount updates the worker nodes count metric
func UpdateWorkerNodesCount(ctx context.Context, value int64) {
	updateCounter(ctx, &workerNodesCount, &lastWorkerNodesCount, value)
}

func updateCounter(ctx context.Context, counter *metric.Int64UpDownCounter, previous *int64, value int64) {
	lastValueMu.Lock()
	defer lastValueMu.Unlock()

	if *counter == nil {
		return
	}

	(*counter).Add(ctx, value-*previous)
	*previous = value
}
