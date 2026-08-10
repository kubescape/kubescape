package cautils

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/stretchr/testify/require"
)

func writeParentWithUnpackedChild(
	t *testing.T,
	parentValues string,
	childValues string,
	childTemplate string,
) (parentRoot, childRoot, childTemplatePath string) {
	t.Helper()

	parentRoot = filepath.Join(t.TempDir(), "parent")
	childRoot = filepath.Join(parentRoot, "charts", "child")
	require.NoError(t, os.MkdirAll(filepath.Join(childRoot, "templates"), 0o755))

	writeManifestFixture(t, parentRoot, "Chart.yaml", `apiVersion: v2
name: parent
version: 0.1.0
dependencies:
  - name: child
    version: 0.1.0
`)
	writeManifestFixture(t, parentRoot, "values.yaml", parentValues)
	writeManifestFixture(t, childRoot, "Chart.yaml", `apiVersion: v2
name: child
version: 0.1.0
`)
	writeManifestFixture(t, childRoot, "values.yaml", childValues)
	childTemplatePath = writeManifestFixture(t, filepath.Join(childRoot, "templates"), "service.yaml", childTemplate)
	return parentRoot, childRoot, childTemplatePath
}

func requireServicePort(t *testing.T, workloads map[string][]workloadinterface.IMetadata, sourcePath string, expected int) {
	t.Helper()

	require.Len(t, workloads[sourcePath], 1)
	spec, ok := workloads[sourcePath][0].GetObject()["spec"].(map[string]any)
	require.True(t, ok)
	ports, ok := spec["ports"].([]any)
	require.True(t, ok)
	require.Len(t, ports, 1)
	port, ok := ports[0].(map[string]any)
	require.True(t, ok)
	require.EqualValues(t, expected, port["port"])
}

func TestLoadResourcesFromHelmCharts_PreservesParentSubchartValues(t *testing.T) {
	tests := []struct {
		name      string
		valueOpts HelmValueOptions
		wantPort  int
	}{
		{
			name:     "parent values file",
			wantPort: 443,
		},
		{
			name:      "nested set override",
			valueOpts: HelmValueOptions{Values: []string{"child.port=8443"}},
			wantPort:  8443,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parentRoot, childRoot, servicePath := writeParentWithUnpackedChild(
				t,
				"child:\n  port: 443\n",
				"port: 80\n",
				`apiVersion: v1
kind: Service
metadata:
  name: child
spec:
  ports:
    - port: {{ .Values.port }}
`,
			)

			workloads, charts, renderedCharts, err := LoadResourcesFromHelmCharts(
				context.Background(), parentRoot, tt.valueOpts,
			)
			require.NoError(t, err)
			require.ElementsMatch(t, []string{parentRoot, childRoot}, renderedCharts)
			requireServicePort(t, workloads, servicePath, tt.wantPort)
			require.Equal(t, "parent", charts[servicePath].Name,
				"the parent chart should own its dependency's rendered template")
			require.Equal(t, parentRoot, charts[servicePath].Path)
		})
	}
}

func TestLoadResourcesFromHelmCharts_DoesNotReintroduceParentSuppressedSubchartOutput(t *testing.T) {
	parentRoot, childRoot, servicePath := writeParentWithUnpackedChild(
		t,
		"child:\n  enabled: false\n",
		"enabled: true\n",
		`{{- if .Values.enabled }}
apiVersion: v1
kind: Service
metadata:
  name: child
spec:
  ports:
    - port: 80
{{- end }}
`,
	)

	workloads, charts, renderedCharts, err := LoadResourcesFromHelmCharts(
		context.Background(), parentRoot, HelmValueOptions{},
	)

	require.NoError(t, err)
	require.ElementsMatch(t, []string{parentRoot, childRoot}, renderedCharts)
	require.NotContains(t, workloads, servicePath,
		"a standalone child render must not recreate output suppressed by its parent values")
	require.NotContains(t, charts, servicePath)
}

func TestLoadResourcesFromHelmCharts_RendersUnrelatedTopLevelCharts(t *testing.T) {
	repoRoot := t.TempDir()
	chartRoots := []string{
		filepath.Join(repoRoot, "first"),
		filepath.Join(repoRoot, "nested", "second"),
	}
	templatePaths := make([]string, 0, len(chartRoots))

	for i, chartRoot := range chartRoots {
		require.NoError(t, os.MkdirAll(filepath.Join(chartRoot, "templates"), 0o755))
		chartName := []string{"first", "second"}[i]
		writeManifestFixture(t, chartRoot, "Chart.yaml", "apiVersion: v2\nname: "+chartName+"\nversion: 0.1.0\n")
		templatePaths = append(templatePaths, writeManifestFixture(
			t,
			filepath.Join(chartRoot, "templates"),
			"configmap.yaml",
			"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: "+chartName+"\n",
		))
	}

	workloads, charts, renderedCharts, err := LoadResourcesFromHelmCharts(
		context.Background(), repoRoot, HelmValueOptions{},
	)

	require.NoError(t, err)
	require.ElementsMatch(t, chartRoots, renderedCharts)
	for i, sourcePath := range templatePaths {
		require.Len(t, workloads[sourcePath], 1)
		require.Equal(t, chartRoots[i], charts[sourcePath].Path)
	}
}

func TestLoadResourcesFromHelmCharts_RendersChildAfterParentRenderFailure(t *testing.T) {
	parentRoot, childRoot, servicePath := writeParentWithUnpackedChild(
		t,
		"child:\n  port: 443\n",
		"port: 80\n",
		`apiVersion: v1
kind: Service
metadata:
  name: child
spec:
  ports:
    - port: {{ .Values.port }}
`,
	)
	require.NoError(t, os.MkdirAll(filepath.Join(parentRoot, "templates"), 0o755))
	writeManifestFixture(t, filepath.Join(parentRoot, "templates"), "broken.yaml", "{{ if }}\n")

	workloads, charts, renderedCharts, err := LoadResourcesFromHelmCharts(
		context.Background(), parentRoot, HelmValueOptions{},
	)

	require.NoError(t, err)
	require.Equal(t, []string{childRoot}, renderedCharts,
		"a failed parent must not claim ownership of its child fallback")
	requireServicePort(t, workloads, servicePath, 80)
	require.Equal(t, "child", charts[servicePath].Name)
	require.Equal(t, childRoot, charts[servicePath].Path)
}

func TestLoadResourcesFromHelmCharts_RendersChildExcludedFromParentByHelmignore(t *testing.T) {
	parentRoot, childRoot, servicePath := writeParentWithUnpackedChild(
		t,
		"child:\n  port: 443\n",
		"port: 80\n",
		`apiVersion: v1
kind: Service
metadata:
  name: child
spec:
  ports:
    - port: {{ .Values.port }}
`,
	)
	writeManifestFixture(t, parentRoot, ".helmignore", "charts/child\n")
	parentChart, err := NewHelmChart(parentRoot)
	require.NoError(t, err)
	require.Empty(t, parentChart.chart.Dependencies(),
		"the ignored child must not be present in the parent's loaded dependency graph")

	workloads, charts, renderedCharts, err := LoadResourcesFromHelmCharts(
		context.Background(), parentRoot, HelmValueOptions{},
	)

	require.NoError(t, err)
	require.ElementsMatch(t, []string{parentRoot, childRoot}, renderedCharts)
	requireServicePort(t, workloads, servicePath, 80)
	require.Equal(t, "child", charts[servicePath].Name,
		"a child excluded from the parent loader is not owned by that render")
	require.Equal(t, childRoot, charts[servicePath].Path)
	_, statErr := os.Stat(filepath.Join(parentRoot, "charts", "child-0.1.0.tgz"))
	require.ErrorIs(t, statErr, os.ErrNotExist,
		"the fixture must remain an unpacked-child test without a generated archive")
}

func TestHelmChartOwnsUnpackedDependency_UsesLoadedGraph(t *testing.T) {
	parentRoot := filepath.Join(t.TempDir(), "parent")
	childRoot := filepath.Join(parentRoot, "charts", "vendor-directory")
	grandchildRoot := filepath.Join(childRoot, "charts", "nested-directory")
	require.NoError(t, os.MkdirAll(grandchildRoot, 0o755))

	writeManifestFixture(t, parentRoot, "Chart.yaml", "apiVersion: v2\nname: parent\nversion: 0.1.0\n")
	writeManifestFixture(t, childRoot, "Chart.yaml", "apiVersion: v2\nname: actual-child-name\nversion: 0.1.0\n")
	writeManifestFixture(t, grandchildRoot, "Chart.yaml", "apiVersion: v2\nname: actual-grandchild-name\nversion: 0.1.0\n")

	parentChart, err := NewHelmChart(parentRoot)
	require.NoError(t, err)
	require.Len(t, parentChart.chart.Dependencies(), 1)
	require.Len(t, parentChart.chart.Dependencies()[0].Dependencies(), 1)
	require.True(t, parentChart.ownsUnpackedDependency(childRoot),
		"ownership must use the loaded file graph instead of assuming directory name equals chart name")
	require.True(t, parentChart.ownsUnpackedDependency(grandchildRoot),
		"ownership must follow more than one loaded dependency edge")
	require.False(t, parentChart.ownsUnpackedDependency(filepath.Join(childRoot, "examples", "chart")))
}
