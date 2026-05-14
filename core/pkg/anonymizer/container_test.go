package anonymizer

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	corev1 "k8s.io/api/core/v1"
	"github.com/stretchr/testify/assert"
)

func TestAnonymizeContainerList_AnonymizesNamesAndImages(t *testing.T) {
	obj := map[string]interface{}{
		"containers": []interface{}{
			map[string]interface{}{
				"name":  "my-secret-app",
				"image": "private.registry.io/app:v1",
			},
			map[string]interface{}{
				"name":  "sidecar",
				"image": "private.registry.io/sidecar:v1",
			},
		},
	}

	m := NewMapping()
	anonymizeContainerList(obj, "containers", m)

	containers, ok := obj["containers"].([]corev1.Container)
	assert.True(t, ok, "after fix, containers must be []corev1.Container")
	assert.Len(t, containers, 2)
	assert.NotEqual(t, "my-secret-app", containers[0].Name)
	assert.NotEqual(t, "private.registry.io/app:v1", containers[0].Image)
	assert.NotEqual(t, "sidecar", containers[1].Name)
	assert.NotEqual(t, "private.registry.io/sidecar:v1", containers[1].Image)
	assert.Contains(t, containers[0].Name, "ctr-")
	assert.Contains(t, containers[0].Image, "img-")
}

func TestAnonymizeContainerMetadata_AnonymizesContainerNamesAndImages(t *testing.T) {
	resource := workloadinterface.NewWorkloadObj(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":      "my-pod",
			"namespace": "default",
		},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "secret-container",
					"image": "private.io/app:v1",
				},
			},
		},
	})

	m := NewMapping()
	anonymizeContainerMetadata(resource, m)

	obj := resource.GetObject()
	spec := obj["spec"].(map[string]interface{})
	containers, ok := spec["containers"].([]corev1.Container)
	assert.True(t, ok)
	assert.Len(t, containers, 1)
	assert.NotEqual(t, "secret-container", containers[0].Name)
	assert.NotEqual(t, "private.io/app:v1", containers[0].Image)
	assert.Contains(t, containers[0].Name, "ctr-")
	assert.Contains(t, containers[0].Image, "img-")
}

func TestAnonymizeContainerList_MissingKey(t *testing.T) {
	obj := map[string]interface{}{}
	m := NewMapping()
	anonymizeContainerList(obj, "containers", m)
}

func TestAnonymizeContainerList_NilValue(t *testing.T) {
	obj := map[string]interface{}{"containers": nil}
	m := NewMapping()
	anonymizeContainerList(obj, "containers", m)
}

func TestAnonymizeEphemeralContainerList_AnonymizesNamesAndImages(t *testing.T) {
	// Simulate runtime shape: []interface{} with map[string]interface{} items
	obj := map[string]interface{}{
		"ephemeralContainers": []interface{}{
			map[string]interface{}{
				"name":  "debug-container",
				"image": "private.registry.io/debug:v1",
			},
		},
	}

	m := NewMapping()
	anonymizeEphemeralContainerList(obj, "ephemeralContainers", m)

	containers, ok := obj["ephemeralContainers"].([]corev1.EphemeralContainer)
	assert.True(t, ok, "after fix, ephemeral containers must be []corev1.EphemeralContainer")
	assert.Len(t, containers, 1)
	assert.NotEqual(t, "debug-container", containers[0].Name)
	assert.NotEqual(t, "private.registry.io/debug:v1", containers[0].Image)
	assert.Contains(t, containers[0].Name, "ctr-")
	assert.Contains(t, containers[0].Image, "img-")
}
