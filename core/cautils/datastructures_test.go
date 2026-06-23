package cautils

import (
	"context"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/prioritization"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEstimateClusterSize(t *testing.T) {
	tests := []struct {
		name     string
		input    K8SResources
		expected int
	}{
		{
			name:     "nil map",
			input:    nil,
			expected: 0,
		},
		{
			name:     "empty map",
			input:    K8SResources{},
			expected: 0,
		},
		{
			name: "single group with resources",
			input: K8SResources{
				"apps/v1/deployments": {"id1", "id2", "id3"},
			},
			expected: 3,
		},
		{
			name: "multiple groups",
			input: K8SResources{
				"apps/v1/deployments": {"id1", "id2"},
				"v1/pods":             {"id3", "id4", "id5"},
				"v1/services":         {"id6"},
			},
			expected: 6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, estimateClusterSize(tt.input))
		})
	}
}

func TestNewOPASessionObjMock(t *testing.T) {
	obj := NewOPASessionObjMock()

	require.NotNil(t, obj)
	assert.NotNil(t, obj.AllResources)
	assert.NotNil(t, obj.ResourcesResult)
	assert.NotNil(t, obj.ResourcesPrioritized)
	assert.NotNil(t, obj.Report)
	assert.NotNil(t, obj.Metadata)
	assert.Nil(t, obj.Policies)
	assert.Nil(t, obj.K8SResources)
}

func TestSetNumberOfWorkerNodes(t *testing.T) {
	t.Run("initializes ClusterContextMetadata when nil", func(t *testing.T) {
		obj := NewOPASessionObjMock()
		obj.Metadata.ContextMetadata.ClusterContextMetadata = nil

		obj.SetNumberOfWorkerNodes(5)

		require.NotNil(t, obj.Metadata.ContextMetadata.ClusterContextMetadata)
		assert.Equal(t, 5, obj.Metadata.ContextMetadata.ClusterContextMetadata.NumberOfWorkerNodes)
	})

	t.Run("updates existing ClusterContextMetadata", func(t *testing.T) {
		obj := NewOPASessionObjMock()
		obj.Metadata.ContextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{
			NumberOfWorkerNodes: 3,
		}

		obj.SetNumberOfWorkerNodes(10)
		assert.Equal(t, 10, obj.Metadata.ContextMetadata.ClusterContextMetadata.NumberOfWorkerNodes)
	})
}

func TestSetMapNamespaceToNumberOfResources(t *testing.T) {
	t.Run("initializes maps when nil", func(t *testing.T) {
		obj := NewOPASessionObjMock()
		obj.Metadata.ContextMetadata.ClusterContextMetadata = nil

		nsMap := map[string]int{"default": 10, "kube-system": 20}
		obj.SetMapNamespaceToNumberOfResources(nsMap)

		require.NotNil(t, obj.Metadata.ContextMetadata.ClusterContextMetadata)
		assert.Equal(t, nsMap, obj.Metadata.ContextMetadata.ClusterContextMetadata.MapNamespaceToNumberOfResources)
	})

	t.Run("replaces existing map", func(t *testing.T) {
		obj := NewOPASessionObjMock()
		obj.Metadata.ContextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{
			MapNamespaceToNumberOfResources: map[string]int{"old": 1},
		}

		newMap := map[string]int{"new": 42}
		obj.SetMapNamespaceToNumberOfResources(newMap)
		assert.Equal(t, newMap, obj.Metadata.ContextMetadata.ClusterContextMetadata.MapNamespaceToNumberOfResources)
	})
}

func TestSetTopWorkloads(t *testing.T) {
	t.Run("empty prioritized resources", func(t *testing.T) {
		obj := NewOPASessionObjMock()
		obj.SetTopWorkloads()

		assert.Empty(t, obj.TopWorkloadsByScore)
	})

	t.Run("fewer resources than TopWorkloadsNumber", func(t *testing.T) {
		obj := NewOPASessionObjMock()
		obj.ResourcesPrioritized = map[string]prioritization.PrioritizedResource{
			"res1": {ResourceID: "res1", Score: 80},
		}
		obj.ResourceSource = map[string]reporthandling.Source{}

		obj.SetTopWorkloads()

		assert.Len(t, obj.TopWorkloadsByScore, 1)
	})

	t.Run("nil report gets initialized", func(t *testing.T) {
		obj := NewOPASessionObjMock()
		obj.Report = nil
		obj.ResourcesPrioritized = map[string]prioritization.PrioritizedResource{
			"res1": {ResourceID: "res1", Score: 50},
		}
		obj.ResourceSource = map[string]reporthandling.Source{}

		obj.SetTopWorkloads()

		require.NotNil(t, obj.Report)
	})
}

func TestSetTopWorkloads_Idempotent(t *testing.T) {
	obj := NewOPASessionObjMock()

	obj.ResourcesPrioritized = map[string]prioritization.PrioritizedResource{
		"res1": {ResourceID: "res1", Score: 100},
		"res2": {ResourceID: "res2", Score: 90},
	}

	obj.ResourceSource = map[string]reporthandling.Source{}

	obj.SetTopWorkloads()

	firstLen := len(obj.TopWorkloadsByScore)

	obj.SetTopWorkloads()

	assert.Len(t, obj.TopWorkloadsByScore, firstLen)
}

func TestNewOPASessionObj(t *testing.T) {
	ctx := context.Background()
	frameworks := []reporthandling.Framework{}
	k8sResources := K8SResources{"group/version/kind": []string{"id1", "id2"}}
	scanInfo := &ScanInfo{
		ScanID:           "test-scan-id",
		OmitRawResources: true,
		TriggeredByCLI:   true,
	}
	sessionObj := NewOPASessionObj(ctx, frameworks, k8sResources, scanInfo)
	assert.NotNil(t, sessionObj)
	assert.Equal(t, "test-scan-id", sessionObj.SessionID)
	assert.Equal(t, true, sessionObj.OmitRawResources)
	assert.Equal(t, true, sessionObj.TriggeredByCLI)
	assert.Equal(t, k8sResources, sessionObj.K8SResources)
}
