package anonymizer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestAnonymizeContainerList(t *testing.T) {
	tests := []struct {
		name           string
		key            string
		obj            map[string]interface{}
		expectChanged  bool
		expectedLength int
	}{
		{
			name: "regular containers",
			key:  "containers",
			obj: map[string]interface{}{
				"containers": []corev1.Container{
					{Name: "api", Image: "nginx:1.25"},
					{Name: "worker", Image: "busybox:1.36"},
				},
			},
			expectChanged:  true,
			expectedLength: 2,
		},
		{
			name: "init containers",
			key:  "initContainers",
			obj: map[string]interface{}{
				"initContainers": []corev1.Container{
					{Name: "setup", Image: "alpine:3.19"},
				},
			},
			expectChanged:  true,
			expectedLength: 1,
		},
		{
			name: "missing key",
			key:  "containers",
			obj: map[string]interface{}{
				"volumes": []string{"config"},
			},
		},
		{
			name: "wrong value type",
			key:  "containers",
			obj: map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{"name": "api", "image": "nginx:1.25"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapping := NewMapping()
			anonymizeContainerList(tt.obj, tt.key, mapping)

			rawContainers, ok := tt.obj[tt.key]
			if !tt.expectChanged {
				if ok {
					_, typed := rawContainers.([]corev1.Container)
					assert.False(t, typed)
				}
				return
			}

			containers, ok := rawContainers.([]corev1.Container)
			assert.True(t, ok)
			assert.Len(t, containers, tt.expectedLength)
			for _, container := range containers {
				assert.NotEmpty(t, container.Name)
				assert.NotEmpty(t, container.Image)
				assert.Regexp(t, "^ctr-[a-f0-9]{8}$", container.Name)
				assert.Regexp(t, "^img-[a-f0-9]{8}$", container.Image)
			}
		})
	}
}

func TestAnonymizeEphemeralContainerList(t *testing.T) {
	tests := []struct {
		name          string
		obj           map[string]interface{}
		expectChanged bool
	}{
		{
			name: "ephemeral containers",
			obj: map[string]interface{}{
				"ephemeralContainers": []corev1.EphemeralContainer{
					{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debugger", Image: "busybox:1.36"}},
				},
			},
			expectChanged: true,
		},
		{
			name: "wrong value type",
			obj: map[string]interface{}{
				"ephemeralContainers": []corev1.Container{
					{Name: "debugger", Image: "busybox:1.36"},
				},
			},
		},
		{
			name: "missing key",
			obj:  map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapping := NewMapping()
			anonymizeEphemeralContainerList(tt.obj, "ephemeralContainers", mapping)

			rawContainers, ok := tt.obj["ephemeralContainers"]
			if !tt.expectChanged {
				if ok {
					_, typed := rawContainers.([]corev1.EphemeralContainer)
					assert.False(t, typed)
				}
				return
			}

			containers, ok := rawContainers.([]corev1.EphemeralContainer)
			assert.True(t, ok)
			assert.Len(t, containers, 1)
			assert.Regexp(t, "^ctr-[a-f0-9]{8}$", containers[0].Name)
			assert.Regexp(t, "^img-[a-f0-9]{8}$", containers[0].Image)
		})
	}
}
