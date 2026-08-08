package core

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/stretchr/testify/assert"
)

func TestContainerImagesIncludesAllContainerTypes(t *testing.T) {
	pod := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "all-container-types", "namespace": "default"},
		"spec": map[string]any{
			"containers": []any{
				map[string]any{"name": "app", "image": "regular:v1"},
				map[string]any{"name": "sidecar", "image": "shared:v1"},
			},
			"initContainers": []any{
				map[string]any{"name": "setup", "image": "init:v1"},
				map[string]any{"name": "shared-init", "image": "shared:v1"},
			},
			"ephemeralContainers": []any{
				map[string]any{"name": "debugger", "image": "debug:v1"},
				map[string]any{"name": "shared-debugger", "image": "shared:v1"},
			},
		},
	})

	images, err := containerImages(pod)

	assert.NoError(t, err)
	assert.Equal(t,
		[]string{"regular:v1", "shared:v1", "init:v1", "shared:v1", "debug:v1", "shared:v1"},
		images,
	)
}

func TestContainerImagesSupportsPodTemplates(t *testing.T) {
	deployment := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "deployment", "namespace": "default"},
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"containers":     []any{map[string]any{"name": "app", "image": "deployment:v1"}},
					"initContainers": []any{map[string]any{"name": "setup", "image": "deployment-init:v1"}},
				},
			},
		},
	})

	images, err := containerImages(deployment)

	assert.NoError(t, err)
	assert.Equal(t, []string{"deployment:v1", "deployment-init:v1"}, images)
}

func TestContainerImagesCollectsOtherCategoriesAfterOneFails(t *testing.T) {
	tests := []struct {
		name      string
		spec      map[string]any
		want      []string
		wantError string
	}{
		{
			name: "regular containers fail",
			spec: map[string]any{
				"containers":          "not-a-list",
				"initContainers":      []any{map[string]any{"name": "setup", "image": "init:v1"}},
				"ephemeralContainers": []any{map[string]any{"name": "debugger", "image": "debug:v1"}},
			},
			want:      []string{"init:v1", "debug:v1"},
			wantError: "failed to get regular containers",
		},
		{
			name: "init containers fail",
			spec: map[string]any{
				"containers":          []any{map[string]any{"name": "app", "image": "regular:v1"}},
				"initContainers":      "not-a-list",
				"ephemeralContainers": []any{map[string]any{"name": "debugger", "image": "debug:v1"}},
			},
			want:      []string{"regular:v1", "debug:v1"},
			wantError: "failed to get init containers",
		},
		{
			name: "ephemeral containers fail",
			spec: map[string]any{
				"containers":          []any{map[string]any{"name": "app", "image": "regular:v1"}},
				"initContainers":      []any{map[string]any{"name": "setup", "image": "init:v1"}},
				"ephemeralContainers": "not-a-list",
			},
			want:      []string{"regular:v1", "init:v1"},
			wantError: "failed to get ephemeral containers",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := workloadinterface.NewWorkloadObj(map[string]any{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata":   map[string]any{"name": "partial", "namespace": "default"},
				"spec":       tt.spec,
			})

			images, err := containerImages(pod)

			assert.ErrorContains(t, err, tt.wantError)
			assert.ElementsMatch(t, tt.want, images)
		})
	}
}
