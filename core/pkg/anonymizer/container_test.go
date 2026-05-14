package anonymizer

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestAnonymizeContainerMetadata(t *testing.T) {
	tests := []struct {
		name     string
		object   map[string]interface{}
		validate func(t *testing.T, spec map[string]interface{})
	}{
		{
			name: "typed containers should be anonymized",
			object: map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []corev1.Container{
						{
							Name:  "payment-api",
							Image: "nginx:latest",
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]interface{}) {
				containers, ok := spec["containers"].([]corev1.Container)
				assert.True(t, ok, "expected typed containers")
				assert.Len(t, containers, 1)

				assert.NotEqual(t, "payment-api", containers[0].Name)
				assert.NotEqual(t, "nginx:latest", containers[0].Image)
				assert.Contains(t, containers[0].Name, "ctr-")
				assert.Contains(t, containers[0].Image, "img-")
			},
		},
		{
			name: "unstructured containers should be anonymized",
			object: map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"name":  "payment-api",
							"image": "nginx:latest",
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]interface{}) {
				containers, ok := spec["containers"].([]interface{})
				assert.True(t, ok, "expected unstructured containers")
				assert.Len(t, containers, 1)

				container, ok := containers[0].(map[string]interface{})
				assert.True(t, ok, "expected unstructured container map")

				assert.NotEqual(t, "payment-api", container["name"])
				assert.NotEqual(t, "nginx:latest", container["image"])
				assert.Contains(t, container["name"], "ctr-")
				assert.Contains(t, container["image"], "img-")
			},
		},
		{
			name: "typed init containers should be anonymized",
			object: map[string]interface{}{
				"spec": map[string]interface{}{
					"initContainers": []corev1.Container{
						{
							Name:  "init-db",
							Image: "postgres:latest",
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]interface{}) {
				containers, ok := spec["initContainers"].([]corev1.Container)
				assert.True(t, ok, "expected typed init containers")
				assert.Len(t, containers, 1)

				assert.NotEqual(t, "init-db", containers[0].Name)
				assert.NotEqual(t, "postgres:latest", containers[0].Image)
				assert.Contains(t, containers[0].Name, "ctr-")
				assert.Contains(t, containers[0].Image, "img-")
			},
		},
		{
			name: "typed ephemeral containers should be anonymized",
			object: map[string]interface{}{
				"spec": map[string]interface{}{
					"ephemeralContainers": []corev1.EphemeralContainer{
						{
							EphemeralContainerCommon: corev1.EphemeralContainerCommon{
								Name:  "debug-shell",
								Image: "busybox:latest",
							},
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]interface{}) {
				containers, ok := spec["ephemeralContainers"].([]corev1.EphemeralContainer)
				assert.True(t, ok, "expected typed ephemeral containers")
				assert.Len(t, containers, 1)

				assert.NotEqual(t, "debug-shell", containers[0].Name)
				assert.NotEqual(t, "busybox:latest", containers[0].Image)
				assert.Contains(t, containers[0].Name, "ctr-")
				assert.Contains(t, containers[0].Image, "img-")
			},
		},
		{
			name: "unstructured ephemeral containers should be anonymized",
			object: map[string]interface{}{
				"spec": map[string]interface{}{
					"ephemeralContainers": []interface{}{
						map[string]interface{}{
							"name":  "debug-shell",
							"image": "busybox:latest",
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]interface{}) {
				containers, ok := spec["ephemeralContainers"].([]interface{})
				assert.True(t, ok, "expected unstructured ephemeral containers")
				assert.Len(t, containers, 1)

				container, ok := containers[0].(map[string]interface{})
				assert.True(t, ok, "expected unstructured ephemeral container map")

				assert.NotEqual(t, "debug-shell", container["name"])
				assert.NotEqual(t, "busybox:latest", container["image"])
				assert.Contains(t, container["name"], "ctr-")
				assert.Contains(t, container["image"], "img-")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mapping := NewMapping()
			resource := workloadinterface.NewWorkloadObj(test.object)

			anonymizeContainerMetadata(resource, mapping)

			spec, ok := resource.GetObject()["spec"].(map[string]interface{})
			assert.True(t, ok, "expected spec to be a map[string]interface{}")

			test.validate(t, spec)
		})
	}
}

func TestAnonymizeContainerList_MissingKey(t *testing.T) {
	obj := map[string]interface{}{}
	mapping := NewMapping()

	assert.NotPanics(t, func() {
		anonymizeContainerList(obj, "containers", mapping)
	})
}

func TestAnonymizeContainerList_NilValue(t *testing.T) {
	obj := map[string]interface{}{
		"containers": nil,
	}
	mapping := NewMapping()

	assert.NotPanics(t, func() {
		anonymizeContainerList(obj, "containers", mapping)
	})
}

func TestAnonymizeContainerList_InvalidType(t *testing.T) {
	obj := map[string]interface{}{
		"containers": "invalid",
	}
	mapping := NewMapping()

	assert.NotPanics(t, func() {
		anonymizeContainerList(obj, "containers", mapping)
	})
}
