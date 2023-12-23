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
	METER_NAME         = "github.com/kubescape/kubescape/v3"
	METRIC_NAME_PREFIX = "kubescape"
)

var initOnce sync.Once

// Metrics are defined here
var (
	kubernetesResourcesCount metric.Int64UpDownCounter
	workerNodesCount         metric.Int64UpDownCounter
)

// Init initializes the metrics
func Init() {
	initOnce.Do(func() {
		var err error
		meterProvider := otel.GetMeterProvider()
		meter := meterProvider.Meter(METER_NAME)
		metricName := func(name string) string {
			return strings.Join([]string{METRIC_NAME_PREFIX, name}, "_")
		}

		if kubernetesResourcesCount, err = meter.Int64UpDownCounter(metricName("kubernetes_resources_count")); err != nil {
			logger.L().Error("failed to register instrument", helpers.Error(err))
		}

		if workerNodesCount, err = meter.Int64UpDownCounter(metricName("worker_nodes_count")); err != nil {
			logger.L().Error("failed to register instrument", helpers.Error(err))
		}
	})
}

// UpdateKubernetesResourcesCount updates the kubernetes resources count metric
func UpdateKubernetesResourcesCount(ctx context.Context, value int64) {
	if kubernetesResourcesCount != nil {
		kubernetesResourcesCount.Add(ctx, value)
	}
}

// UpdateWorkerNodesCount updates the worker nodes count metric
func UpdateWorkerNodesCount(ctx context.Context, value int64) {
	if workerNodesCount != nil {
		workerNodesCount.Add(ctx, value)
	}
}
