package cautils

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	helmchartutil "helm.sh/helm/v3/pkg/chartutil"
	k8sversion "k8s.io/apimachinery/pkg/util/version"
	componentversion "k8s.io/component-base/version"
)

const (
	capabilitiesChartGatewayAPI = "gateway.networking.k8s.io/v1"

	capabilitiesChartVersionTemplate = `apiVersion: v1
kind: ConfigMap
metadata:
  name: rendered-for
data:
  kubeVersion: {{ .Capabilities.KubeVersion.Version | quote }}
`
	capabilitiesChartVersionGatedTemplate = `{{- if semverCompare ">=1.25-0" .Capabilities.KubeVersion.Version }}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
        - name: web
          image: nginx:1.27
          securityContext: {privileged: true}
{{- end }}
`
	capabilitiesChartAPIGatedTemplate = `{{- if .Capabilities.APIVersions.Has "gateway.networking.k8s.io/v1" }}
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: web-public
spec:
  parentRefs: [{name: public-gw}]
  rules: [{backendRefs: [{name: web, port: 80}]}]
{{- end }}
`
)

// writeCapabilitiesChart writes a chart with one template that reports the Kubernetes version it
// was rendered for, one that only renders for Kubernetes >= 1.25, and one that only renders when
// the Gateway API is available. kubeVersion is the chart's own constraint; empty declares none.
func writeCapabilitiesChart(t *testing.T, kubeVersion string) string {
	t.Helper()
	dir := t.TempDir()
	chartYAML := "apiVersion: v2\nname: capabilities\nversion: 0.1.0\n"
	if kubeVersion != "" {
		chartYAML += "kubeVersion: \"" + kubeVersion + "\"\n"
	}
	writeManifestFixture(t, dir, "Chart.yaml", chartYAML)
	templates := filepath.Join(dir, "templates")
	require.NoError(t, os.Mkdir(templates, 0o700))
	writeManifestFixture(t, templates, "version.yaml", capabilitiesChartVersionTemplate)
	writeManifestFixture(t, templates, "web.yaml", capabilitiesChartVersionGatedTemplate)
	writeManifestFixture(t, templates, "route.yaml", capabilitiesChartAPIGatedTemplate)
	return dir
}

// renderCapabilitiesChart returns the "Kind/name" of every rendered resource and the Kubernetes
// version the templates saw.
func renderCapabilitiesChart(t *testing.T, chartDir string, capOpts HelmCapabilityOptions) ([]string, string) {
	t.Helper()
	chart, err := NewHelmChart(chartDir)
	require.NoError(t, err)
	workloads, errs := chart.GetWorkloadsWithCapabilities(chart.GetDefaultValues(), helmchartutil.ReleaseOptions{}, capOpts)
	require.Empty(t, errs)

	var rendered []string
	var kubeVersion string
	for _, sourceWorkloads := range workloads {
		for _, workload := range sourceWorkloads {
			rendered = append(rendered, workload.GetKind()+"/"+workload.GetName())
			if workload.GetKind() == "ConfigMap" {
				data, _ := workload.GetObject()["data"].(map[string]any)
				kubeVersion, _ = data["kubeVersion"].(string)
			}
		}
	}
	slices.Sort(rendered)
	return rendered, kubeVersion
}

func TestHelmCapabilities_ZeroOptionsKeepHelmDefaults(t *testing.T) {
	chartDir := writeCapabilitiesChart(t, "")

	rendered, kubeVersion := renderCapabilitiesChart(t, chartDir, HelmCapabilityOptions{})

	assert.Equal(t, []string{"ConfigMap/rendered-for"}, rendered)
	assert.Equal(t, helmchartutil.DefaultCapabilities.KubeVersion.Version, kubeVersion)

	chart, err := NewHelmChart(chartDir)
	require.NoError(t, err)
	viaOptions, errs := chart.GetWorkloadsWithOptions(chart.GetDefaultValues(), helmchartutil.ReleaseOptions{})
	require.Empty(t, errs)
	viaCapabilities, errs := chart.GetWorkloadsWithCapabilities(chart.GetDefaultValues(), helmchartutil.ReleaseOptions{}, HelmCapabilityOptions{})
	require.Empty(t, errs)
	assert.Equal(t, viaOptions, viaCapabilities)
}

func TestHelmCapabilities_KubeVersionSelectsVersionGatedTemplates(t *testing.T) {
	chartDir := writeCapabilitiesChart(t, "")

	rendered, kubeVersion := renderCapabilitiesChart(t, chartDir, HelmCapabilityOptions{KubeVersion: "1.31"})
	assert.Equal(t, []string{"ConfigMap/rendered-for", "Deployment/web"}, rendered)
	assert.Equal(t, "v1.31", kubeVersion)

	rendered, kubeVersion = renderCapabilitiesChart(t, chartDir, HelmCapabilityOptions{KubeVersion: "v1.24.3"})
	assert.Equal(t, []string{"ConfigMap/rendered-for"}, rendered)
	assert.Equal(t, "v1.24.3", kubeVersion)
}

func TestHelmCapabilities_APIVersionsSelectAPIGatedTemplates(t *testing.T) {
	chartDir := writeCapabilitiesChart(t, "")
	builtIn := len(helmchartutil.DefaultVersionSet)
	require.False(t, helmchartutil.DefaultVersionSet.Has(capabilitiesChartGatewayAPI))

	rendered, kubeVersion := renderCapabilitiesChart(t, chartDir, HelmCapabilityOptions{APIVersions: []string{capabilitiesChartGatewayAPI}})

	assert.Equal(t, []string{"ConfigMap/rendered-for", "HTTPRoute/web-public"}, rendered)
	assert.Equal(t, helmchartutil.DefaultCapabilities.KubeVersion.Version, kubeVersion, "API versions alone leave the Kubernetes version at its default")

	// The extra API versions belong to this render only: Helm's package-level set is shared by
	// every other chart in the scan and by every later scan in the process.
	assert.Len(t, helmchartutil.DefaultVersionSet, builtIn)
	assert.False(t, helmchartutil.DefaultVersionSet.Has(capabilitiesChartGatewayAPI))
	rendered, _ = renderCapabilitiesChart(t, chartDir, HelmCapabilityOptions{})
	assert.Equal(t, []string{"ConfigMap/rendered-for"}, rendered)
}

func TestHelmCapabilities_ChartKubeVersionConstraint(t *testing.T) {
	chartDir := writeCapabilitiesChart(t, ">=1.29.0-0")
	chart, err := NewHelmChart(chartDir)
	require.NoError(t, err)

	t.Run("an explicit version outside the constraint fails as Helm does", func(t *testing.T) {
		workloads, errs := chart.GetWorkloadsWithCapabilities(chart.GetDefaultValues(), helmchartutil.ReleaseOptions{}, HelmCapabilityOptions{KubeVersion: "1.20"})
		assert.Empty(t, workloads)
		require.Len(t, errs, 1)
		assert.EqualError(t, errs[0], "chart requires kubeVersion: >=1.29.0-0 which is incompatible with Kubernetes v1.20")
	})

	t.Run("an explicit version inside the constraint renders", func(t *testing.T) {
		rendered, kubeVersion := renderCapabilitiesChart(t, chartDir, HelmCapabilityOptions{KubeVersion: "1.31"})
		assert.Equal(t, []string{"ConfigMap/rendered-for", "Deployment/web"}, rendered)
		assert.Equal(t, "v1.31", kubeVersion)
	})

	t.Run("without an explicit version the chart picks the newest it allows", func(t *testing.T) {
		newest := "v" + componentversion.DefaultKubeBinaryVersion + ".0"

		rendered, kubeVersion := renderCapabilitiesChart(t, chartDir, HelmCapabilityOptions{})
		assert.Equal(t, []string{"ConfigMap/rendered-for", "Deployment/web"}, rendered)
		assert.Equal(t, newest, kubeVersion)

		rendered, kubeVersion = renderCapabilitiesChart(t, chartDir, HelmCapabilityOptions{APIVersions: []string{capabilitiesChartGatewayAPI}})
		assert.Equal(t, []string{"ConfigMap/rendered-for", "Deployment/web", "HTTPRoute/web-public"}, rendered)
		assert.Equal(t, newest, kubeVersion)
	})
}

func TestHelmCapabilities_InvalidKubeVersion(t *testing.T) {
	chart, err := NewHelmChart(writeCapabilitiesChart(t, ""))
	require.NoError(t, err)

	workloads, errs := chart.GetWorkloadsWithCapabilities(chart.GetDefaultValues(), helmchartutil.ReleaseOptions{}, HelmCapabilityOptions{KubeVersion: "latest"})

	assert.Empty(t, workloads)
	require.Len(t, errs, 1)
	assert.ErrorContains(t, errs[0], `"latest" is not a Kubernetes version`)
}

func TestValidateHelmKubeVersion(t *testing.T) {
	for _, version := range []string{"", "1.31", "v1.31", "1.31.4", "v1.31.4"} {
		assert.NoErrorf(t, ValidateHelmKubeVersion(version), "version %q", version)
	}
	for _, version := range []string{"latest", "one.two", "v", "1.x"} {
		assert.ErrorContainsf(t, ValidateHelmKubeVersion(version), "is not a Kubernetes version", "version %q", version)
	}
}

func TestHelmValueOptions_CapabilityOptions(t *testing.T) {
	assert.True(t, HelmValueOptions{}.IsEmpty())
	assert.True(t, HelmValueOptions{}.CapabilityOptions().IsEmpty())
	assert.False(t, HelmValueOptions{KubeVersion: "1.31"}.IsEmpty())
	assert.False(t, HelmValueOptions{APIVersions: []string{capabilitiesChartGatewayAPI}}.IsEmpty())

	opts := HelmValueOptions{KubeVersion: "1.31", APIVersions: []string{capabilitiesChartGatewayAPI}}
	assert.Equal(t, HelmCapabilityOptions{KubeVersion: "1.31", APIVersions: []string{capabilitiesChartGatewayAPI}}, opts.CapabilityOptions())
}

func TestLoadResourcesFromHelmCharts_WithCapabilities(t *testing.T) {
	chartDir := writeCapabilitiesChart(t, "")
	webPath := filepath.Join(chartDir, "templates", "web.yaml")
	routePath := filepath.Join(chartDir, "templates", "route.yaml")

	sourceToWorkloads, _, _, err := LoadResourcesFromHelmCharts(context.Background(), chartDir, HelmValueOptions{})
	require.NoError(t, err)
	assert.NotContains(t, sourceToWorkloads, webPath)
	assert.NotContains(t, sourceToWorkloads, routePath)

	sourceToWorkloads, _, _, err = LoadResourcesFromHelmCharts(context.Background(), chartDir, HelmValueOptions{
		KubeVersion: "1.31",
		APIVersions: []string{capabilitiesChartGatewayAPI},
	})
	require.NoError(t, err)
	require.Len(t, sourceToWorkloads[webPath], 1)
	assert.Equal(t, "Deployment", sourceToWorkloads[webPath][0].GetKind())
	require.Len(t, sourceToWorkloads[routePath], 1)
	assert.Equal(t, "HTTPRoute", sourceToWorkloads[routePath][0].GetKind())
}

// TestLoadResourcesFromHelmCharts_BadKubeVersionFailsFast mirrors
// TestLoadResourcesFromHelmCharts_BadOverrideFailsFast: a version that cannot be parsed fails the
// load instead of being reported as one render failure per chart.
func TestLoadResourcesFromHelmCharts_BadKubeVersionFailsFast(t *testing.T) {
	chartDir := writeCapabilitiesChart(t, "")

	_, _, _, err := LoadResourcesFromHelmCharts(context.Background(), chartDir, HelmValueOptions{KubeVersion: "latest"})

	require.Error(t, err)
	assert.ErrorContains(t, err, "Helm capabilities")
	assert.ErrorContains(t, err, `"latest" is not a Kubernetes version`)
}

func TestHelmCapabilities_DefaultKubeVersionFromChartConstraint(t *testing.T) {
	newest, err := newestKubeVersion()
	require.NoError(t, err)
	newestVersion := "v" + componentversion.DefaultKubeBinaryVersion + ".0"
	helmDefault := helmchartutil.DefaultCapabilities.KubeVersion.Version

	tests := []struct {
		name        string
		constraint  string
		wantVersion string
		wantWeb     bool
	}{
		{name: "lower bound only", constraint: ">=1.25.0-0", wantVersion: newestVersion, wantWeb: true},
		{name: "lower bound without prerelease suffix", constraint: ">= 1.25", wantVersion: newestVersion, wantWeb: true},
		{name: "upper bound", constraint: ">=1.25.0-0 <1.30.0-0", wantVersion: "v1.29.0", wantWeb: true},
		{name: "wildcard minor", constraint: "1.27.x", wantVersion: "v1.27.0", wantWeb: true},
		{name: "alternatives take the newest", constraint: "<1.19.0-0 || >=1.26.0-0", wantVersion: newestVersion, wantWeb: true},
		{name: "only older than the default", constraint: "<1.19.0-0", wantVersion: "v1.18.0"},
		{name: "no constraint keeps the default", constraint: "", wantVersion: helmDefault},
		{name: "patch-level constraint keeps the default", constraint: "~1.29.3", wantVersion: helmDefault},
		{name: "minor newer than the vendored libraries keeps the default", constraint: fmt.Sprintf(">=1.%d.0-0", newest.Minor()+1), wantVersion: helmDefault},
		{name: "unparsable constraint keeps the default", constraint: "not a constraint", wantVersion: helmDefault},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rendered, kubeVersion := renderCapabilitiesChart(t, writeCapabilitiesChart(t, tt.constraint), HelmCapabilityOptions{})

			assert.Equal(t, tt.wantVersion, kubeVersion)
			assert.Equal(t, tt.wantWeb, slices.Contains(rendered, "Deployment/web"), "rendered: %v", rendered)
			assert.Equal(t, helmDefault, helmchartutil.DefaultCapabilities.KubeVersion.Version, "the shared default must not change")
		})
	}
}

// TestHelmCapabilities_UnconstrainedChartKeepsLibraryDefaults pins that a chart without a
// kubeVersion constraint, rendered without options, still goes to Helm with nil capabilities.
func TestHelmCapabilities_UnconstrainedChartKeepsLibraryDefaults(t *testing.T) {
	chart, err := NewHelmChart(writeCapabilitiesChart(t, ""))
	require.NoError(t, err)

	caps, err := chart.capabilities(HelmCapabilityOptions{})
	require.NoError(t, err)
	assert.Nil(t, caps)
	assert.Nil(t, chart.defaultKubeVersion())

	constrained, err := NewHelmChart(writeCapabilitiesChart(t, ">=1.25.0-0"))
	require.NoError(t, err)
	caps, err = constrained.capabilities(HelmCapabilityOptions{})
	require.NoError(t, err)
	require.NotNil(t, caps)
	assert.Equal(t, helmchartutil.DefaultVersionSet, caps.APIVersions, "a version from the constraint adds no API versions")
}

func TestHelmCapabilities_ExplicitKubeVersionWinsOverConstraint(t *testing.T) {
	chartDir := writeCapabilitiesChart(t, ">=1.25.0-0")

	rendered, kubeVersion := renderCapabilitiesChart(t, chartDir, HelmCapabilityOptions{KubeVersion: "1.28"})
	assert.Equal(t, []string{"ConfigMap/rendered-for", "Deployment/web"}, rendered)
	assert.Equal(t, "v1.28", kubeVersion)

	chart, err := NewHelmChart(chartDir)
	require.NoError(t, err)
	_, errs := chart.GetWorkloadsWithCapabilities(chart.GetDefaultValues(), helmchartutil.ReleaseOptions{}, HelmCapabilityOptions{KubeVersion: "1.24"})
	require.Len(t, errs, 1)
	assert.EqualError(t, errs[0], "chart requires kubeVersion: >=1.25.0-0 which is incompatible with Kubernetes v1.24")
}

func TestNewestKubeVersion(t *testing.T) {
	newest, err := newestKubeVersion()
	require.NoError(t, err)

	helmDefault, err := k8sversion.ParseGeneric(helmchartutil.DefaultCapabilities.KubeVersion.Version)
	require.NoError(t, err)
	assert.True(t, newest.GreaterThan(helmDefault), "vendored Kubernetes %s should be newer than Helm's default %s", newest, helmDefault)
}

// TestLoadResourcesFromHelmCharts_DefaultsToChartKubeVersion is the chart from #4141: it declares
// kubeVersion ">=1.29.0-0" and gates a privileged Deployment on Kubernetes >= 1.25. Without any
// flag that Deployment used to be dropped, so the scan passed.
func TestLoadResourcesFromHelmCharts_DefaultsToChartKubeVersion(t *testing.T) {
	chartDir := writeCapabilitiesChart(t, ">=1.29.0-0")
	webPath := filepath.Join(chartDir, "templates", "web.yaml")
	routePath := filepath.Join(chartDir, "templates", "route.yaml")

	sourceToWorkloads, _, renderedCharts, err := LoadResourcesFromHelmCharts(context.Background(), chartDir, HelmValueOptions{})

	require.NoError(t, err)
	assert.Equal(t, []string{chartDir}, renderedCharts)
	require.Len(t, sourceToWorkloads[webPath], 1)
	assert.Equal(t, "Deployment", sourceToWorkloads[webPath][0].GetKind())
	assert.NotContains(t, sourceToWorkloads, routePath, "API-gated templates still need --api-versions")
}
