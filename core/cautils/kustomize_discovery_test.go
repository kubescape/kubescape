package cautils

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestListKustomizeInputsDiscoversNestedHelmOwnership(t *testing.T) {
	repoRoot := t.TempDir()
	appDir := filepath.Join(repoRoot, "app")
	require.NoError(t, os.MkdirAll(appDir, 0o750))
	writeManifestFixture(t, appDir, "kustomization.yaml", `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
helmGlobals:
  chartHome: vendor/charts
helmCharts:
  - name: app
    releaseName: app
`)

	inputs, errs := listKustomizeInputs(repoRoot)
	require.Empty(t, errs)
	require.Equal(t, []string{appDir}, inputs)

	ownedCharts, err := KustomizeHelmChartDirectories(context.Background(), inputs[0])
	require.NoError(t, err)
	require.Equal(t, []string{filepath.Join(appDir, "vendor", "charts", "app")}, ownedCharts)
}

func TestKustomizeInputOwnershipIncludesCRDAndHelmValuesInputs(t *testing.T) {
	root := t.TempDir()
	for _, directory := range []string{
		filepath.Join(root, "charts", "explicit"),
		filepath.Join(root, "charts", "defaulted"),
		filepath.Join(root, "values"),
	} {
		require.NoError(t, os.MkdirAll(directory, 0o750))
	}
	writeManifestFixture(t, root, "kustomization.yaml", `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
crds:
  - schema.yaml
helmGlobals:
  chartHome: charts
helmCharts:
  - name: explicit
    releaseName: explicit
    valuesFile: values/override.yaml
    additionalValuesFiles:
      - values/additional.yaml
  - name: defaulted
    releaseName: defaulted
`)
	writeManifestFixture(t, root, "schema.yaml", "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: widgets.example.com\n")
	writeManifestFixture(t, filepath.Join(root, "values"), "override.yaml", "replicas: 2\n")
	writeManifestFixture(t, filepath.Join(root, "values"), "additional.yaml", "image: nginx:1.27\n")
	for _, chart := range []string{"explicit", "defaulted"} {
		chartDirectory := filepath.Join(root, "charts", chart)
		writeManifestFixture(t, chartDirectory, "Chart.yaml", "apiVersion: v2\nname: "+chart+"\nversion: 0.1.0\n")
		writeManifestFixture(t, chartDirectory, "values.yaml", "{}\n")
	}

	ownership, err := KustomizeInputOwnershipForPath(context.Background(), root)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{
		filepath.Join(root, "kustomization.yaml"),
		filepath.Join(root, "schema.yaml"),
		filepath.Join(root, "values", "override.yaml"),
		filepath.Join(root, "values", "additional.yaml"),
		filepath.Join(root, "charts", "defaulted", "values.yaml"),
	}, ownership.SourcePaths)
}
