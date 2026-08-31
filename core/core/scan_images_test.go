package core

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/stretchr/testify/assert"
)

func TestScanImagesSkipsInitializationWhenNoImagesFound(t *testing.T) {
	emptyPod := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "empty", "namespace": "default"},
		"spec": map[string]any{
			"containers":          []any{},
			"initContainers":      []any{},
			"ephemeralContainers": []any{},
		},
	})
	images, containerErrors := getAllWorkloadImages(emptyPod)
	assert.Empty(t, images)
	assert.Empty(t, containerErrors)

	tests := []struct {
		name     string
		scanType cautils.ScanTypes
		scanData *cautils.OPASessionObj
	}{
		{
			name:     "single workload",
			scanType: cautils.ScanTypeWorkload,
			scanData: &cautils.OPASessionObj{SingleResourceScan: emptyPod},
		},
		{
			name:     "all resources",
			scanType: cautils.ScanTypeFramework,
			scanData: &cautils.OPASessionObj{
				AllResources: map[string]workloadinterface.IMetadata{"empty": emptyPod},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				assert.NoError(t, scanImages(tt.scanType, tt.scanData, context.Background(), nil, nil, nil))
			})
		})
	}
}
