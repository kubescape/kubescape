package cautils

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/locationresolver"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeJSONTemplateChart writes a chart whose manifests are JSON templates.
// Helm renders every template whatever its extension and reads .json like
// .yaml (chart.hasManifestExtension), so both manifests must be scanned.
// NOTES.txt renders text that is not a manifest, and disabled.json renders
// nothing; neither may produce a workload or an error.
func writeJSONTemplateChart(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeManifestFixture(t, dir, "Chart.yaml", "apiVersion: v2\nname: json-templates\nversion: 0.1.0\n")
	writeManifestFixture(t, dir, "values.yaml", "replicas: 2\nimage: nginx:1.27\nextra:\n  enabled: false\n")
	templates := filepath.Join(dir, "templates")
	require.NoError(t, os.Mkdir(templates, 0o700))
	writeManifestFixture(t, templates, "deployment.json", `{
  "apiVersion": "apps/v1",
  "kind": "Deployment",
  "metadata": {"name": {{ printf "%s-web" .Release.Name | quote }}},
  "spec": {
    "replicas": {{ .Values.replicas }},
    "selector": {"matchLabels": {"app": "web"}},
    "template": {
      "metadata": {"labels": {"app": "web"}},
      "spec": {"containers": [{"name": "web", "image": {{ .Values.image | quote }}}]}
    }
  }
}
`)
	writeManifestFixture(t, templates, "static.json", `{
  "apiVersion": "v1",
  "kind": "ConfigMap",
  "metadata": {
    "name": "static-config",
    "labels": {
      "marker": "static"
    }
  },
  "data": {"key": "value"}
}
`)
	writeManifestFixture(t, templates, "disabled.json", `{{- if .Values.extra.enabled }}
{"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "extra"}}
{{- end }}
`)
	writeManifestFixture(t, templates, "NOTES.txt", "Installed {{ .Release.Name }}.\n")
	return dir
}

func TestGetWorkloadsRendersJSONTemplates(t *testing.T) {
	chartDir := writeJSONTemplateChart(t)
	chart, err := NewHelmChart(chartDir)
	require.NoError(t, err)

	fileToWorkloads, errs := chart.GetWorkloadsWithDefaultValues()
	require.Empty(t, errs)

	templatedPath := filepath.Join(chartDir, "templates", "deployment.json")
	staticPath := filepath.Join(chartDir, "templates", "static.json")
	require.Len(t, fileToWorkloads, 2, "only the two JSON manifests produce workloads, not NOTES.txt or the disabled template")

	templated := fileToWorkloads[templatedPath]
	require.Len(t, templated, 1)
	assert.Equal(t, "Deployment", templated[0].GetKind())
	assert.Equal(t, "release-name-web", templated[0].GetName())
	object, err := json.Marshal(templated[0].GetObject())
	require.NoError(t, err)
	assert.Contains(t, string(object), `"replicas":2`)
	assert.Contains(t, string(object), `"image":"nginx:1.27"`)
	assert.Equal(t, templatedPath, templated[0].(*localworkload.LocalWorkload).GetPath(),
		"a templated file keeps the bare path, as a YAML template does")

	static := fileToWorkloads[staticPath]
	require.Len(t, static, 1)
	assert.Equal(t, "static-config", static[0].GetName())
	assert.Equal(t, staticPath+":0", static[0].(*localworkload.LocalWorkload).GetPath(),
		"a static JSON template is unchanged by rendering, so its document index is safe to claim")

	resolver, err := locationresolver.NewPathLocationResolver(staticPath)
	require.NoError(t, err)
	location, err := resolver.ResolveLocation(".metadata.labels.marker", 0)
	require.NoError(t, err)
	assert.Equal(t, 7, location.Line, "the marker label is on line 7 of static.json")
}

// TestLoadResourcesFromHelmCharts_IncludesJSONTemplates covers the scan path:
// a rendered chart's templates are excluded from the plain-file pass, so a
// JSON template the renderer skipped was missing from the scan altogether.
func TestLoadResourcesFromHelmCharts_IncludesJSONTemplates(t *testing.T) {
	chartDir := writeJSONTemplateChart(t)

	sourceToWorkloads, sourceToChart, _, err := LoadResourcesFromHelmCharts(context.TODO(), chartDir, HelmValueOptions{Values: []string{"replicas=5"}})
	require.NoError(t, err)

	templatedPath := filepath.Join(chartDir, "templates", "deployment.json")
	require.Contains(t, sourceToWorkloads, templatedPath)
	require.Len(t, sourceToWorkloads[templatedPath], 1)
	object, err := json.Marshal(sourceToWorkloads[templatedPath][0].GetObject())
	require.NoError(t, err)
	assert.Contains(t, string(object), `"replicas":5`, "--set overrides apply to JSON templates")

	c, ok := sourceToChart[templatedPath]
	require.True(t, ok, "a JSON template's workloads are attributed to their chart")
	assert.Equal(t, "json-templates", c.Name)
	assert.Equal(t, "templates/deployment.json", c.Provenance.TemplateFile)
	assert.Contains(t, c.Provenance.ValuesPaths, "replicas")
}
