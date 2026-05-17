package metrics

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetMetricsForTest(t *testing.T) {
	t.Helper()

	savedInitOnce := initOnce
	savedKubernetesResourcesCount := kubernetesResourcesCount
	savedWorkerNodesCount := workerNodesCount

	initOnce = sync.Once{}
	kubernetesResourcesCount = nil
	workerNodesCount = nil

	t.Cleanup(func() {
		initOnce = savedInitOnce
		kubernetesResourcesCount = savedKubernetesResourcesCount
		workerNodesCount = savedWorkerNodesCount
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
