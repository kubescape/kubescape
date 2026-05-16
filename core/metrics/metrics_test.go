package metrics

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInit(t *testing.T) {
	// Init should be safe to call multiple times thanks to sync.Once.
	assert.NotPanics(t, func() { Init() })
	assert.NotPanics(t, func() { Init() })
}

func TestUpdateKubernetesResourcesCount_NilCounter(t *testing.T) {
	// Before Init(), the counter is nil. Update should not panic.
	saved := kubernetesResourcesCount
	kubernetesResourcesCount = nil
	defer func() { kubernetesResourcesCount = saved }()

	assert.NotPanics(t, func() {
		UpdateKubernetesResourcesCount(context.Background(), 5)
	})
}

func TestUpdateWorkerNodesCount_NilCounter(t *testing.T) {
	// Before Init(), the counter is nil. Update should not panic.
	saved := workerNodesCount
	workerNodesCount = nil
	defer func() { workerNodesCount = saved }()

	assert.NotPanics(t, func() {
		UpdateWorkerNodesCount(context.Background(), 3)
	})
}

func TestUpdateKubernetesResourcesCount_AfterInit(t *testing.T) {
	Init()
	// After Init(), the counter is set. Update should not panic.
	assert.NotPanics(t, func() {
		UpdateKubernetesResourcesCount(context.Background(), 10)
	})
}

func TestUpdateWorkerNodesCount_AfterInit(t *testing.T) {
	Init()
	// After Init(), the counter is set. Update should not panic.
	assert.NotPanics(t, func() {
		UpdateWorkerNodesCount(context.Background(), 4)
	})
}
