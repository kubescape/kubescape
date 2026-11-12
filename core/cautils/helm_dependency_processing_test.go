package cautils

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/stretchr/testify/require"
)

const childServiceTemplate = `apiVersion: v1
kind: Service
metadata:
  name: {{ .Chart.Name }}
spec:
  ports:
    - port: {{ .Values.port }}
`

// writeParentWithDependencies writes a parent chart whose Chart.yaml declares
// dependencies (the YAML list items, indented under "dependencies:"), with
// one unpacked child chart under charts/child.
func writeParentWithDependencies(t *testing.T, dependencies, parentValues string) (parentRoot, childRoot string) {
	t.Helper()

	parentRoot = filepath.Join(t.TempDir(), "parent")
	childRoot = filepath.Join(parentRoot, "charts", "child")
	require.NoError(t, os.MkdirAll(filepath.Join(childRoot, "templates"), 0o755))

	writeManifestFixture(t, parentRoot, "Chart.yaml", "apiVersion: v2\nname: parent\nversion: 0.1.0\ndependencies:\n"+dependencies)
	writeManifestFixture(t, parentRoot, "values.yaml", parentValues)
	writeManifestFixture(t, childRoot, "Chart.yaml", "apiVersion: v2\nname: child\nversion: 0.1.0\n")
	writeManifestFixture(t, childRoot, "values.yaml", "port: 80\n")
	writeManifestFixture(t, filepath.Join(childRoot, "templates"), "service.yaml", childServiceTemplate)
	return parentRoot, childRoot
}

func TestLoadResourcesFromHelmCharts_SkipsDisabledSubcharts(t *testing.T) {
	tests := []struct {
		name         string
		dependencies string
		parentValues string
		valueOpts    HelmValueOptions
		wantRendered bool
	}{
		{
			name:         "condition false in parent values",
			dependencies: "  - name: child\n    version: 0.1.0\n    condition: child.enabled\n",
			parentValues: "child:\n  enabled: false\n",
		},
		{
			name:         "condition false through --set",
			dependencies: "  - name: child\n    version: 0.1.0\n    condition: child.enabled\n",
			parentValues: "child:\n  enabled: true\n",
			valueOpts:    HelmValueOptions{Values: []string{"child.enabled=false"}},
		},
		{
			name:         "tag false",
			dependencies: "  - name: child\n    version: 0.1.0\n    tags:\n      - optional\n",
			parentValues: "tags:\n  optional: false\n",
		},
		{
			name:         "condition true",
			dependencies: "  - name: child\n    version: 0.1.0\n    condition: child.enabled\n",
			parentValues: "child:\n  enabled: true\n",
			wantRendered: true,
		},
		{
			name:         "condition unset",
			dependencies: "  - name: child\n    version: 0.1.0\n    condition: child.enabled\n",
			parentValues: "{}\n",
			wantRendered: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parentRoot, childRoot := writeParentWithDependencies(t, tt.dependencies, tt.parentValues)
			servicePath := filepath.Join(childRoot, "templates", "service.yaml")

			workloads, charts, renderedCharts, err := LoadResourcesFromHelmCharts(
				context.Background(), parentRoot, tt.valueOpts,
			)

			require.NoError(t, err)
			require.ElementsMatch(t, []string{parentRoot, childRoot}, renderedCharts,
				"the parent owns its dependency whether or not the dependency is enabled")
			if tt.wantRendered {
				requireServicePort(t, workloads, servicePath, 80)
				require.Equal(t, parentRoot, charts[servicePath].Path)
				return
			}
			require.NotContains(t, workloads, servicePath,
				"helm template does not render a disabled dependency, so it must not be scanned")
			require.NotContains(t, charts, servicePath)
		})
	}
}

func TestLoadResourcesFromHelmCharts_RendersAliasedSubcharts(t *testing.T) {
	parentRoot, childRoot := writeParentWithDependencies(t,
		"  - name: child\n    version: 0.1.0\n    alias: cache\n"+
			"  - name: child\n    version: 0.1.0\n    alias: session\n",
		"cache:\n  port: 443\nsession:\n  port: 8443\n",
	)
	servicePath := filepath.Join(childRoot, "templates", "service.yaml")

	for name, workspace := range map[string]string{"without workspace": "", "inside workspace": parentRoot} {
		t.Run(name, func(t *testing.T) {
			workloads, charts, renderedCharts, err := LoadResourcesFromHelmChartsFiltered(
				context.Background(), parentRoot, HelmValueOptions{}, nil, nil, workspace,
			)

			require.NoError(t, err)
			require.ElementsMatch(t, []string{parentRoot, childRoot}, renderedCharts)
			// Helm renders each alias as its own subchart, named after the
			// alias and reading the values under the alias's key. Both renders
			// come from the template on disk, so they are reported against it.
			require.Len(t, workloads, 1)
			require.Len(t, workloads[servicePath], 2)
			wantPorts := map[string]int{"cache": 443, "session": 8443}
			for _, workload := range workloads[servicePath] {
				require.Contains(t, wantPorts, workload.GetName())
				require.Equal(t, servicePath, workload.(*localworkload.LocalWorkload).GetPath())
				requireServicePort(t, map[string][]workloadinterface.IMetadata{servicePath: {workload}},
					servicePath, wantPorts[workload.GetName()])
				delete(wantPorts, workload.GetName())
			}
			require.Equal(t, parentRoot, charts[servicePath].Path)
			require.Equal(t, "templates/service.yaml", charts[servicePath].Provenance.TemplateFile)
		})
	}
}

func TestLoadResourcesFromHelmCharts_AppliesSubchartImportValues(t *testing.T) {
	parentRoot, childRoot := writeParentWithDependencies(t,
		"  - name: child\n    version: 0.1.0\n    import-values:\n      - child: shared\n        parent: imported\n",
		"{}\n",
	)
	writeManifestFixture(t, childRoot, "values.yaml", "port: 80\nshared:\n  port: 9443\n")
	require.NoError(t, os.MkdirAll(filepath.Join(parentRoot, "templates"), 0o755))
	parentService := writeManifestFixture(t, filepath.Join(parentRoot, "templates"), "service.yaml", `apiVersion: v1
kind: Service
metadata:
  name: parent
spec:
  ports:
    - port: {{ .Values.imported.port }}
`)

	workloads, _, _, err := LoadResourcesFromHelmCharts(
		context.Background(), parentRoot, HelmValueOptions{},
	)

	require.NoError(t, err)
	requireServicePort(t, workloads, parentService, 9443)
}

func TestHelmChartGetWorkloads_DoesNotModifyLoadedChart(t *testing.T) {
	parentRoot, childRoot := writeParentWithDependencies(t,
		"  - name: child\n    version: 0.1.0\n    condition: child.enabled\n"+
			"  - name: child\n    version: 0.1.0\n    alias: cache\n",
		"child:\n  enabled: true\n",
	)
	servicePath := filepath.Join(childRoot, "templates", "service.yaml")

	chart, err := NewHelmChart(parentRoot)
	require.NoError(t, err)

	disabled := map[string]any{"child": map[string]any{"enabled": false}}
	workloads, errs := chart.GetWorkloads(disabled)
	require.Empty(t, errs)
	requireServicePort(t, workloads, servicePath, 80)
	require.Equal(t, "cache", workloads[servicePath][0].GetName())

	// A render must not leave the chart with its disabled dependency removed
	// or its dependencies renamed: the next render, ownership checks and
	// provenance all read the chart as it was loaded.
	workloads, errs = chart.GetWorkloadsWithDefaultValues()
	require.Empty(t, errs)
	require.Len(t, workloads[servicePath], 2)
	require.ElementsMatch(t, []string{"child", "cache"},
		[]string{workloads[servicePath][0].GetName(), workloads[servicePath][1].GetName()})
	require.True(t, chart.ownsUnpackedDependency(childRoot))
	require.Contains(t, chart.Provenance(), servicePath)
	require.Len(t, chart.chart.Dependencies(), 1)
	require.Equal(t, "child", chart.chart.Dependencies()[0].Name())
	require.Equal(t, "child", chart.chart.Metadata.Dependencies[1].Name)
}
