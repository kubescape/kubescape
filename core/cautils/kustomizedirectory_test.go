package cautils

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				_ = os.WriteFile(tempFile, []byte(""), 0600)
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

func TestKustomizeHelmChartDirectories_CustomHomeDeduplicatesPhysicalChart(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "kustomization.yaml", `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
helmGlobals:
  chartHome: vendor/charts
helmCharts:
  - name: app
    releaseName: first
  - name: app
    releaseName: second
`)

	directories, err := KustomizeHelmChartDirectories(context.Background(), root)
	require.NoError(t, err)
	assert.Equal(t, []string{filepath.Join(root, "vendor", "charts", "app")}, directories)
}

func TestKustomizeHelmChartDirectories_VersionedRepositoryChart(t *testing.T) {
	root := t.TempDir()
	writeManifestFixture(t, root, "kustomization.yaml", `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
helmGlobals:
  chartHome: vendor/charts
helmCharts:
  - name: app
    version: 1.2.3
    repo: https://charts.example.com
    releaseName: app
`)

	directories, err := KustomizeHelmChartDirectories(context.Background(), root)
	require.NoError(t, err)
	assert.Equal(t, []string{
		filepath.Join(root, "vendor", "charts", "app-1.2.3", "app"),
	}, directories)
}

func TestKustomizeHelmChartDirectories_ChartHomeAndDownloadLayout(t *testing.T) {
	tests := []struct {
		name        string
		chartHome   func(string) string
		chartFields string
		expected    func(string) string
	}{
		{
			name:      "absolute chart home",
			chartHome: func(root string) string { return filepath.Join(root, "absolute-charts") },
			expected:  func(root string) string { return filepath.Join(root, "absolute-charts", "app") },
		},
		{
			name:        "repository without version uses regular chart home",
			chartHome:   func(string) string { return "charts" },
			chartFields: "    repo: https://charts.example.com\n",
			expected:    func(root string) string { return filepath.Join(root, "charts", "app") },
		},
		{
			name:        "version without repository uses regular chart home",
			chartHome:   func(string) string { return "charts" },
			chartFields: "    version: 1.2.3\n",
			expected:    func(root string) string { return filepath.Join(root, "charts", "app") },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			chartHome := tt.chartHome(root)
			writeManifestFixture(t, root, "kustomization.yaml", fmt.Sprintf(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
helmGlobals:
  chartHome: %q
helmCharts:
  - name: app
%s    releaseName: app
`, chartHome, tt.chartFields))

			directories, err := KustomizeHelmChartDirectories(context.Background(), root)
			require.NoError(t, err)
			assert.Equal(t, []string{tt.expected(root)}, directories)
		})
	}
}

func TestAppendOwnedHelmChartTree_PreservesPartialDiscovery(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "charts", "dependency")
	require.NoError(t, os.MkdirAll(nested, 0o750))

	seen := map[string]struct{}{}
	var directories []string
	appendOwnedHelmChartTreeWithLister(
		context.Background(),
		root,
		seen,
		&directories,
		func(string) ([]string, []error) {
			return []string{nested}, []error{errors.New("synthetic partial walk failure")}
		},
	)

	assert.Equal(t, []string{root, nested}, directories)
}

func TestKustomizeHelmChartDirectories_TraversesSelectedLocalGraph(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "base")
	component := filepath.Join(root, "component")
	require.NoError(t, os.MkdirAll(base, 0o750))
	require.NoError(t, os.MkdirAll(component, 0o750))

	writeManifestFixture(t, root, "kustomization.yaml", `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - base
components:
  - component
`)
	writeManifestFixture(t, base, "kustomization.yaml", `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
helmCharts:
  - name: base-app
    releaseName: base-app
`)
	writeManifestFixture(t, component, "kustomization.yaml", `apiVersion: kustomize.config.k8s.io/v1alpha1
kind: Component
helmGlobals:
  chartHome: vendor/charts
helmCharts:
  - name: component-app
    releaseName: component-app
`)

	directories, err := KustomizeHelmChartDirectories(context.Background(), root)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{
		filepath.Join(base, "charts", "base-app"),
		filepath.Join(component, "vendor", "charts", "component-app"),
	}, directories)
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
				spec, ok := obj["spec"].(map[string]any)
				assert.True(t, ok, "deployment should have spec")

				template, ok := spec["template"].(map[string]any)
				assert.True(t, ok, "deployment should have template")

				templateSpec, ok := template["spec"].(map[string]any)
				assert.True(t, ok, "template should have spec")

				containers, ok := templateSpec["containers"].([]any)
				assert.True(t, ok, "template spec should have containers")
				assert.NotEmpty(t, containers, "should have at least one container")

				container, ok := containers[0].(map[string]any)
				assert.True(t, ok, "container should be a map")

				resources, ok := container["resources"].(map[string]any)
				assert.True(t, ok, "container should have resources (from base)")

				limits, ok := resources["limits"].(map[string]any)
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

func TestKustomizeDirectoryWithHelmCharts(t *testing.T) {
	helmPath := filepath.Join(kustomizeTestdataPath(), "helm")

	assert.True(t, isKustomizeDirectory(helmPath), "helm directory should be detected as kustomize directory")

	kd := NewKustomizeDirectory(helmPath)
	workloads, errs := kd.GetWorkloads(helmPath)

	for _, err := range errs {
		assert.NotContains(t, err.Error(), "must specify --enable-helm", "kustomize should run with helm enabled")
		if strings.Contains(err.Error(), `exec: "helm": executable file not found`) {
			t.Skip("helm is not installed in test environment")
		}
		if strings.Contains(err.Error(), "unknown shorthand flag") || strings.Contains(err.Error(), "unknown flag") || strings.Contains(err.Error(), "unable to run: 'helm version -c --short'") {
			t.Skip("installed helm version is incompatible with the kustomize version used (removed -c/--short flags)")
		}
	}

	assert.Empty(t, errs, "kustomize with helm charts should render without errors")
	assert.NotEmpty(t, workloads, "rendered workloads should include resources from helm chart")

	var configMapFound bool
	for _, wls := range workloads {
		for _, wl := range wls {
			if wl.GetKind() == "ConfigMap" && wl.GetName() == "test-config" {
				configMapFound = true
			}
		}
	}
	assert.True(t, configMapFound, "helm chart ConfigMap should be present in rendered workloads")
}
