package cautils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetKustomizeDirectoryName(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name                string
		args                args
		want                string
		createKustomization bool
	}{
		{
			name: "kustomize directory",
			args: args{
				path: os.TempDir(),
			},
			createKustomization: true,
			want:                os.TempDir(),
		},
		{
			name: "not kustomize directory",
			args: args{
				path: os.TempDir(),
			},
			createKustomization: false,
			want:                "",
		},
		{
			name: "inexistent directory",
			args: args{
				path: filepath.Join(os.TempDir(), "bla"),
			},
			createKustomization: false,
			want:                "",
		},
		{
			name: "empty",
			args: args{
				path: "",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempFile := filepath.Join(tt.args.path, "kustomization.yaml")
			if tt.createKustomization {
				_ = os.WriteFile(tempFile, []byte(""), 0644)
			}
			if got := getKustomizeDirectoryName(tt.args.path); got != tt.want {
				t.Errorf("GetKustomizeDirectoryName() = %v, want %v", got, tt.want)
			}
			os.Remove(tempFile)
		})
	}
}

func kustomizeTestdataPath() string {
	o, _ := os.Getwd()
	return filepath.Join(o, "testdata", "kustomize")
}

// TestKustomizeOverlayWithBase tests that kustomize overlays can properly load
// resources from base directories. This is the main fix for issue #1617.
func TestKustomizeOverlayWithBase(t *testing.T) {
	overlayPath := filepath.Join(kustomizeTestdataPath(), "overlays", "prod")

	// Verify it's detected as a kustomize directory
	assert.True(t, isKustomizeDirectory(overlayPath), "overlay should be detected as kustomize directory")

	// Create kustomize directory and get workloads
	kd := NewKustomizeDirectory(overlayPath)
	workloads, errs := kd.GetWorkloads(overlayPath)

	// Should not have errors - this was failing before the fix because
	// overlays couldn't load resources from parent base directories
	assert.Empty(t, errs, "should not have errors loading overlay with base reference")

	// Should have workloads from the rendered overlay
	assert.NotEmpty(t, workloads, "should have workloads from rendered kustomize overlay")

	// The overlay should have produced exactly one deployment with the merged configuration
	var deploymentFound bool
	for _, wls := range workloads {
		for _, wl := range wls {
			if wl.GetKind() == "Deployment" && wl.GetName() == "test-app" {
				deploymentFound = true

				// Verify the deployment has the resource limits from the base
				obj := wl.GetObject()
				spec, ok := obj["spec"].(map[string]interface{})
				assert.True(t, ok, "deployment should have spec")

				template, ok := spec["template"].(map[string]interface{})
				assert.True(t, ok, "deployment should have template")

				templateSpec, ok := template["spec"].(map[string]interface{})
				assert.True(t, ok, "template should have spec")

				containers, ok := templateSpec["containers"].([]interface{})
				assert.True(t, ok, "template spec should have containers")
				assert.NotEmpty(t, containers, "should have at least one container")

				container, ok := containers[0].(map[string]interface{})
				assert.True(t, ok, "container should be a map")

				resources, ok := container["resources"].(map[string]interface{})
				assert.True(t, ok, "container should have resources (from base)")

				limits, ok := resources["limits"].(map[string]interface{})
				assert.True(t, ok, "resources should have limits")
				assert.Equal(t, "500m", limits["cpu"], "cpu limit should be from base")
				assert.Equal(t, "256Mi", limits["memory"], "memory limit should be from base")

				// Verify overlay modifications were applied
				replicas, ok := spec["replicas"].(int)
				assert.True(t, ok, "replicas should be an int")
				assert.Equal(t, 3, replicas, "replicas should be modified by overlay")
			}
		}
	}
	assert.True(t, deploymentFound, "deployment should be found in rendered output")
}

// TestKustomizeBaseDirectory tests that base directories work on their own
func TestKustomizeBaseDirectory(t *testing.T) {
	basePath := filepath.Join(kustomizeTestdataPath(), "base")

	assert.True(t, isKustomizeDirectory(basePath), "base should be detected as kustomize directory")

	kd := NewKustomizeDirectory(basePath)
	workloads, errs := kd.GetWorkloads(basePath)

	assert.Empty(t, errs, "should not have errors loading base directory")
	assert.NotEmpty(t, workloads, "should have workloads from base directory")
}
