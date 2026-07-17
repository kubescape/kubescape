package cautils

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func onlineBoutiquePath() string {
	o, _ := os.Getwd()
	return filepath.Join(filepath.Dir(o), "..", "examples", "online-boutique")
}

func helmChartPath() string {
	o, _ := os.Getwd()
	return filepath.Join(filepath.Dir(o), "..", "examples", "helm_chart")
}

func TestListFiles(t *testing.T) {

	filesPath := onlineBoutiquePath()

	files, errs := listFiles(filesPath)
	assert.Equal(t, 0, len(errs))
	assert.Equal(t, 13, len(files))
}

func TestLoadResourcesFromFiles(t *testing.T) {
	workloads := LoadResourcesFromFiles(context.Background(), onlineBoutiquePath(), "")
	assert.Equal(t, 12, len(workloads))

	for i, w := range workloads {
		switch filepath.Base(i) {
		case "adservice.yaml":
			assert.Equal(t, 2, len(w))
			assert.Equal(t, "apps/v1//Deployment/adservice", getRelativePath(w[0].GetID()))
			assert.Equal(t, "/v1//Service/adservice", getRelativePath(w[1].GetID()))
		}
	}
}

func TestLoadResourcesFromFiles_SupportsMixedCaseExtensions(t *testing.T) {
	o, _ := os.Getwd()
	testDir := filepath.Join(o, "testdata", "mixed_extensions")
	workloads := LoadResourcesFromFiles(context.Background(), testDir, "")
	assert.Equal(t, 2, len(workloads))

	expectedFiles := []string{
		filepath.Join(testDir, "pod.yaml"),
		filepath.Join(testDir, "service.YAML"),
	}

	for _, ef := range expectedFiles {
		_, ok := workloads[ef]
		assert.True(t, ok, "Expected workload for file %s", ef)
	}
}

func helmChartLayoutPath() string {
	o, _ := os.Getwd()
	return filepath.Join(o, "testdata", "helm_chart_layout")
}

// The helm render owns the templates, so the plain-YAML loader must leave them alone: they would
// otherwise duplicate the rendered workloads and warn on every "{{ ... }}" action. Everything else
// under the chart is not rendered by helm and stays plainly scanned.
func TestLoadResourcesFromFiles_SkipsHelmTemplates(t *testing.T) {
	testDir := helmChartLayoutPath()
	workloads := LoadResourcesFromFiles(context.Background(), testDir, testDir)

	expectedFiles := []string{
		filepath.Join(testDir, "plain-pod.yaml"),
		filepath.Join(testDir, "mychart", "crds", "widget.yaml"),
	}
	for _, ef := range expectedFiles {
		_, ok := workloads[ef]
		assert.Truef(t, ok, "expected workload for file %s", ef)
	}
	assert.Equal(t, len(expectedFiles), len(workloads))
}

// Scanning a chart directly must skip its templates the same way, since charts are detected
// recursively rather than only at the scanned path.
func TestLoadResourcesFromFiles_SkipsHelmTemplatesOfScannedChart(t *testing.T) {
	testDir := filepath.Join(helmChartLayoutPath(), "mychart")
	workloads := LoadResourcesFromFiles(context.Background(), testDir, testDir)

	expectedFile := filepath.Join(testDir, "crds", "widget.yaml")
	_, ok := workloads[expectedFile]
	assert.Truef(t, ok, "expected workload for file %s", expectedFile)
	assert.Equal(t, 1, len(workloads))
}

func TestExcludeHelmTemplateFiles(t *testing.T) {
	chart := filepath.Join("repo", "mychart")
	subchart := filepath.Join(chart, "charts", "mysubchart")
	helmDirectories := []string{chart, subchart}

	tests := []struct {
		name     string
		file     string
		excluded bool
	}{
		{
			name:     "chart template is excluded",
			file:     filepath.Join(chart, "templates", "deployment.yaml"),
			excluded: true,
		},
		{
			name:     "nested chart template is excluded",
			file:     filepath.Join(chart, "templates", "rbac", "role.yaml"),
			excluded: true,
		},
		{
			name:     "subchart template is excluded",
			file:     filepath.Join(subchart, "templates", "service.yaml"),
			excluded: true,
		},
		{
			name:     "crd is kept, helm does not render it",
			file:     filepath.Join(chart, "crds", "widget.yaml"),
			excluded: false,
		},
		{
			name:     "chart metadata is kept",
			file:     filepath.Join(chart, "values.yaml"),
			excluded: false,
		},
		{
			name:     "file outside a chart is kept",
			file:     filepath.Join("repo", "plain-pod.yaml"),
			excluded: false,
		},
		{
			name:     "directory sharing the templates prefix is kept",
			file:     filepath.Join(chart, "templates-docs", "example.yaml"),
			excluded: false,
		},
		{
			name:     "chart sharing a name prefix is kept",
			file:     filepath.Join("repo", "mychart-docs", "templates", "example.yaml"),
			excluded: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			remaining := excludeHelmTemplateFiles([]string{tt.file}, helmDirectories)
			if tt.excluded {
				assert.Empty(t, remaining)
			} else {
				assert.Equal(t, []string{tt.file}, remaining)
			}
		})
	}
}

func TestExcludeHelmTemplateFiles_NoCharts(t *testing.T) {
	files := []string{filepath.Join("repo", "templates", "pod.yaml")}
	assert.Equal(t, files, excludeHelmTemplateFiles(files, nil))
}

func TestLoadResourcesFromHelmCharts(t *testing.T) {
	sourceToWorkloads, sourceToChartName, err := LoadResourcesFromHelmCharts(context.Background(), helmChartPath(), HelmValueOptions{})
	assert.NoError(t, err)
	assert.Equal(t, 6, len(sourceToWorkloads))

	for file, workloads := range sourceToWorkloads {

		assert.Equalf(t, 1, len(workloads), "expected 1 workload in file %s", file)

		w := workloads[0]
		assert.True(t, localworkload.IsTypeLocalWorkload(w.GetObject()), "Expected localworkload as object type")
		assert.Equal(t, "kubescape", sourceToChartName[file].Name)
		assert.Equal(t, helmChartPath(), sourceToChartName[file].Path)

		switch filepath.Base(file) {
		case "serviceaccount.yaml":
			assert.Equal(t, "/v1//ServiceAccount/kubescape-discovery", getRelativePath(w.GetID()))
		case "clusterrole.yaml":
			assert.Equal(t, "rbac.authorization.k8s.io/v1//ClusterRole/-kubescape", getRelativePath(w.GetID()))
		case "cronjob.yaml":
			assert.Equal(t, "batch/v1//CronJob/-kubescape", getRelativePath(w.GetID()))
		case "role.yaml":
			assert.Equal(t, "rbac.authorization.k8s.io/v1//Role/-kubescape", getRelativePath(w.GetID()))
		case "rolebinding.yaml":
			assert.Equal(t, "rbac.authorization.k8s.io/v1//RoleBinding/-kubescape", getRelativePath(w.GetID()))
		case "clusterrolebinding.yaml":
			assert.Equal(t, "rbac.authorization.k8s.io/v1//ClusterRoleBinding/-kubescape", getRelativePath(w.GetID()))
		default:
			assert.Failf(t, "missing case for file: %s", filepath.Base(file))
		}
	}
}

func TestLoadFiles(t *testing.T) {
	files, _ := listFiles(onlineBoutiquePath())
	_, err := loadFiles("", files)
	assert.Equal(t, 0, len(err))
}

func TestListDirs(t *testing.T) {
	dirs, _ := listDirs(filepath.Join(onlineBoutiquePath(), "adservice.yaml"))
	assert.Equal(t, 0, len(dirs))

	expectedDirs := []string{filepath.Join("examples", "helm_chart"), filepath.Join("examples", "helm_chart", "templates")}
	dirs, _ = listDirs(helmChartPath())
	assert.Equal(t, len(expectedDirs), len(dirs))
	for i := range expectedDirs {
		assert.Contains(t, dirs[i], expectedDirs[i])
	}
}

func TestLoadFile(t *testing.T) {
	files, _ := listFiles(filepath.Join(onlineBoutiquePath(), "adservice.yaml"))
	assert.Equal(t, 1, len(files))

	_, err := loadFile(files[0])
	assert.NoError(t, err)
}

func getRelativePath(p string) string {
	pp := strings.SplitAfter(p, "api=")
	return pp[1]
}

// Converts a YAML object to a JSON object
func TestConvertYamlToJson(t *testing.T) {
	tests := []struct {
		yamlObj map[any]any
		jsonObj map[string]any
	}{
		{
			yamlObj: map[any]any{
				"name": "John",
				"age":  30,
				"city": "New York",
			},
			jsonObj: map[string]any{
				"name": "John",
				"age":  30,
				"city": "New York",
			},
		},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			assert.Equal(t, tt.jsonObj, convertYamlToJson(tt.yamlObj))
		})
	}
}

func TestIsYaml(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{
			path: "temp.yaml",
			want: true,
		},
		{
			path: "temp.YAML",
			want: true,
		},
		{
			path: "temp.yml",
			want: true,
		},
		{
			path: "temp.Yml",
			want: true,
		},
		{
			path: "temp.Yaml",
			want: true,
		},
		{
			path: "temp.json",
			want: false,
		},
		{
			path: "temp.Json",
			want: false,
		},
		{
			path: "random.txt",
			want: false,
		},
		{
			path: "no-ext",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, IsYaml(tt.path))
		})
	}
}

func TestIsJson(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{
			path: "temp.yaml",
			want: false,
		},
		{
			path: "temp.yml",
			want: false,
		},
		{
			path: "temp.json",
			want: true,
		},
		{
			path: "temp.JSON",
			want: true,
		},
		{
			path: "temp.Json",
			want: true,
		},
		{
			path: "temp.Yaml",
			want: false,
		},
		{
			path: "random.txt",
			want: false,
		},
		{
			path: "no-ext",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, IsJson(tt.path))
		})
	}

}

func TestGetFileFormat(t *testing.T) {
	tests := []struct {
		path string
		want FileFormat
	}{
		{
			path: "temp.yaml",
			want: YAML_FILE_FORMAT,
		},
		{
			path: "temp.YAML",
			want: YAML_FILE_FORMAT,
		},
		{
			path: "temp.yml",
			want: YAML_FILE_FORMAT,
		},
		{
			path: "temp.Yml",
			want: YAML_FILE_FORMAT,
		},
		{
			path: "temp.Yaml",
			want: YAML_FILE_FORMAT,
		},
		{
			path: "temp.json",
			want: JSON_FILE_FORMAT,
		},
		{
			path: "temp.JSON",
			want: JSON_FILE_FORMAT,
		},
		{
			path: "temp.Json",
			want: JSON_FILE_FORMAT,
		},
		{
			path: "random.txt",
			want: "random.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, getFileFormat(tt.path))
		})
	}
}

func TestIsFileAndIsDir(t *testing.T) {
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "test_file.txt")
	err := os.WriteFile(tempFile, []byte("test"), 0644)
	require.NoError(t, err)

	assert.True(t, isDir(tempDir))
	assert.False(t, isFile(tempDir))

	assert.True(t, isFile(tempFile))
	assert.False(t, isDir(tempFile))

	missingPath := filepath.Join(tempDir, "missing-path")
	assert.False(t, isFile(missingPath))
	assert.False(t, isDir(missingPath))
}
