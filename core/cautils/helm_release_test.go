package cautils

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	helmchartutil "helm.sh/helm/v3/pkg/chartutil"
)

func writeHelmReleaseChart(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeManifestFixture(t, dir, "Chart.yaml", "apiVersion: v2\nname: release-defaults\nversion: 0.1.0\n")
	templates := filepath.Join(dir, "templates")
	require.NoError(t, os.Mkdir(templates, 0o700))
	writeManifestFixture(t, templates, "bootstrap.yaml", `{{- if .Release.IsInstall }}
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ .Release.Name }}-bootstrap
  namespace: {{ .Release.Namespace }}
  annotations:
    example.com/revision: {{ .Release.Revision | quote }}
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: bootstrap
          image: busybox:1.36
          securityContext:
            privileged: true
{{- end }}
`)
	writeManifestFixture(t, templates, "context.yaml", `apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Release.Name }}-context
  namespace: {{ .Release.Namespace }}
data:
  install: {{ .Release.IsInstall | quote }}
  upgrade: {{ .Release.IsUpgrade | quote }}
  revision: {{ .Release.Revision | quote }}
`)
	return dir
}

func TestLoadResourcesFromHelmChartsRendersInstallOnlyWorkloads(t *testing.T) {
	dir := writeHelmReleaseChart(t)
	jobPath := filepath.Join(dir, "templates", "bootstrap.yaml")

	for _, tt := range []struct {
		name     string
		opts     HelmValueOptions
		wantName string
		wantNS   string
	}{
		{name: "defaults", wantName: "release-name-bootstrap", wantNS: "default"},
		{
			name:     "release name only",
			opts:     HelmValueOptions{ReleaseName: "shop"},
			wantName: "shop-bootstrap",
			wantNS:   "default",
		},
		{
			name:     "release namespace only",
			opts:     HelmValueOptions{ReleaseNamespace: "staging"},
			wantName: "release-name-bootstrap",
			wantNS:   "staging",
		},
		{
			name:     "explicit release identity",
			opts:     HelmValueOptions{ReleaseName: "shop", ReleaseNamespace: "development"},
			wantName: "shop-bootstrap",
			wantNS:   "development",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			workloads, _, _, err := LoadResourcesFromHelmCharts(context.Background(), dir, tt.opts)
			require.NoError(t, err)
			require.Contains(t, workloads, jobPath, "install-only Job must not be omitted from the scan")
			require.Len(t, workloads[jobPath], 1)
			job := workloads[jobPath][0]
			assert.Equal(t, "Job", job.GetKind())
			assert.Equal(t, tt.wantName, job.GetName())
			assert.Equal(t, tt.wantNS, job.GetNamespace())
			metadata := job.GetObject()["metadata"].(map[string]any)
			annotations := metadata["annotations"].(map[string]any)
			assert.Equal(t, "1", annotations["example.com/revision"])
		})
	}
}

func TestHelmChartRendersInstallByDefault(t *testing.T) {
	dir := writeHelmReleaseChart(t)
	chart, err := NewHelmChart(dir)
	require.NoError(t, err)

	workloads, errs := chart.GetWorkloadsWithDefaultValues()
	require.Empty(t, errs)
	jobPath := filepath.Join(dir, "templates", "bootstrap.yaml")
	require.Contains(t, workloads, jobPath)
	require.Len(t, workloads[jobPath], 1)
	assert.Equal(t, "release-name-bootstrap", workloads[jobPath][0].GetName())
}

func TestHelmChartPreservesExplicitUpgradeOptions(t *testing.T) {
	dir := writeHelmReleaseChart(t)
	chart, err := NewHelmChart(dir)
	require.NoError(t, err)

	workloads, errs := chart.GetWorkloadsWithOptions(chart.GetDefaultValues(), helmchartutil.ReleaseOptions{
		Name:      "shop",
		Namespace: "production",
		Revision:  3,
		IsUpgrade: true,
	})
	require.Empty(t, errs)
	assert.NotContains(t, workloads, filepath.Join(dir, "templates", "bootstrap.yaml"))
	contextPath := filepath.Join(dir, "templates", "context.yaml")
	require.Len(t, workloads[contextPath], 1)
	releaseContext := workloads[contextPath][0]
	assert.Equal(t, "shop-context", releaseContext.GetName())
	assert.Equal(t, "production", releaseContext.GetNamespace())
	assert.Equal(t, map[string]any{"install": "false", "upgrade": "true", "revision": "3"}, releaseContext.GetObject()["data"])
}
