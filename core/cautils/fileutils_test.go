package cautils

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/stretchr/testify/assert"
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
	workloads := LoadResourcesFromFiles(context.TODO(), onlineBoutiquePath(), "")
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

func TestLoadResourcesFromHelmCharts(t *testing.T) {
	sourceToWorkloads, sourceToChartName, _ := LoadResourcesFromHelmCharts(context.TODO(), helmChartPath())
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
		yamlObj map[interface{}]interface{}
		jsonObj map[string]interface{}
	}{
		{
			yamlObj: map[interface{}]interface{}{
				"name": "John",
				"age":  30,
				"city": "New York",
			},
			jsonObj: map[string]interface{}{
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
			path: "temp.json",
			want: false,
		},
		{
			path: "random.txt",
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
			path: "temp.json",
			want: true,
		},
		{
			path: "random.txt",
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
			path: "temp.json",
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
