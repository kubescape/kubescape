package scan_test

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/cmd/scan"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/core/core"
	"github.com/kubescape/opa-utils/reporthandling"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const privilegedManifest = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: default
spec:
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: app
          image: nginx:1.27
          securityContext:
            privileged: true
`

func TestScanPreservesIndependentManifestSources(t *testing.T) {
	root := t.TempDir()
	writeManifestSource(t, filepath.Join(root, "prod", "deployment.yaml"), privilegedManifest)
	writeManifestSource(t, filepath.Join(root, "dev", "deployment.yaml"), strings.ReplaceAll(privilegedManifest, "privileged: true", "privileged: false"))
	writeManifestSource(t, filepath.Join(root, "dev", "kustomization.yaml"), "resources:\n  - deployment.yaml\n")

	report, err := scanManifestSources(t, root)

	assert.ErrorContains(t, err, "scan compliance-score is below permitted threshold")
	assert.Equal(t, map[string]string{
		"prod/deployment.yaml": "failed",
		"dev":                  "passed",
	}, manifestSourceStatuses(t, report))
	assert.Equal(t, float32(50), report.SummaryDetails.ComplianceScore)
}

func TestScanPreservesRawFallbackBesideIndependentKustomize(t *testing.T) {
	root := t.TempDir()
	writeManifestSource(t, filepath.Join(root, "prod", "deployment.yaml"), privilegedManifest)
	writeManifestSource(t, filepath.Join(root, "prod", "kustomization.yaml"), "resources:\n  - deployment.yaml\n  - missing.yaml\n")
	writeManifestSource(t, filepath.Join(root, "dev", "deployment.yaml"), strings.ReplaceAll(privilegedManifest, "privileged: true", "privileged: false"))
	writeManifestSource(t, filepath.Join(root, "dev", "kustomization.yaml"), "resources:\n  - deployment.yaml\n")

	report, err := scanManifestSources(t, root)

	assert.ErrorContains(t, err, "scan compliance-score is below permitted threshold")
	assert.Equal(t, map[string]string{
		"prod/deployment.yaml": "failed",
		"dev":                  "passed",
	}, manifestSourceStatuses(t, report))
}

func TestScanCountsRenderedManifestOnce(t *testing.T) {
	for _, tc := range []struct {
		name     string
		manifest string
		status   string
	}{
		{name: "privileged", manifest: privilegedManifest, status: "failed"},
		{name: "safe", manifest: strings.ReplaceAll(privilegedManifest, "privileged: true", "privileged: false"), status: "passed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeManifestSource(t, filepath.Join(root, "dev", "deployment.yaml"), tc.manifest)
			writeManifestSource(t, filepath.Join(root, "dev", "kustomization.yaml"), "namePrefix: dev-\nresources:\n  - deployment.yaml\n")

			report, err := scanManifestSources(t, root)

			if tc.status == "failed" {
				assert.ErrorContains(t, err, "scan compliance-score is below permitted threshold")
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, map[string]string{"dev": tc.status}, manifestSourceStatuses(t, report))
		})
	}
}

func writeManifestSource(t *testing.T, path, contents string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
}

// The policy is local and deliberately small: discovery, rendering, evaluation,
// reporting, and the compliance gate all run through the real scan command.
func scanManifestSources(t *testing.T, root string) (reporthandlingv2.PostureReport, error) {
	t.Helper()
	// Resolve tenant settings locally so a contributor's kubeconfig is never used.
	t.Setenv("KS_CLOUD_API_URL", "https://api.example.invalid")
	t.Setenv("KS_CLOUD_REPORT_URL", "https://report.example.invalid")
	for _, name := range []string{
		"OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "OTEL_EXPORTER_OTLP_PROTOCOL",
	} {
		t.Setenv(name, "")
	}
	previousConnector := getter.GetKSCloudAPIConnector()
	getter.SetKSCloudAPIConnector(nil)
	t.Cleanup(func() { getter.SetKSCloudAPIConnector(previousConnector) })

	dir := t.TempDir()
	rule := reporthandling.PolicyRule{
		Rule: `package armo_builtins
import rego.v1
deny contains {"alertMessage": "privileged container", "alertObject": {"k8sApiObjects": [resource]}} if {
    resource := input[_]
    resource.spec.template.spec.containers[_].securityContext.privileged == true
}`,
		RuleLanguage: reporthandling.RegoLanguage,
		Match: []reporthandling.RuleMatchObjects{{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"Deployment"},
		}},
	}
	rule.Name = "privileged-container"
	control := reporthandling.Control{ControlID: "C-TEST", BaseScore: 5, Rules: []reporthandling.PolicyRule{rule}}
	control.Name = "Privileged container"
	policy, err := json.Marshal(control)
	require.NoError(t, err)
	policyPath := filepath.Join(dir, "control.json")
	writeManifestSource(t, policyPath, string(policy))
	inputsPath := filepath.Join(dir, "inputs.json")
	writeManifestSource(t, inputsPath, `{"probe":["value"]}`)
	exceptionsPath := filepath.Join(dir, "exceptions.json")
	writeManifestSource(t, exceptionsPath, `[]`)
	outputPath := filepath.Join(dir, "report.json")

	command := scan.GetScanCommand(core.NewKubescape(context.Background()))
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	command.SetArgs([]string{
		"control", "C-TEST", root,
		"--use-from", policyPath, "--controls-config", inputsPath,
		"--exceptions", exceptionsPath, "--submit=false", "--keep-local",
		"--account", "11111111-2222-3333-4444-555555555555", "--access-key", "local-test",
		"--compliance-threshold", "100", "--format", "json", "--output", outputPath,
	})
	scanErr := command.Execute()
	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	var report reporthandlingv2.PostureReport
	require.NoError(t, json.Unmarshal(data, &report))
	return report, scanErr
}

func manifestSourceStatuses(t *testing.T, report reporthandlingv2.PostureReport) map[string]string {
	t.Helper()
	statuses := make(map[string]string)
	for _, result := range report.Results {
		require.Len(t, result.AssociatedControls, 1)
		statuses[result.ResourceID] = string(result.AssociatedControls[0].Status.InnerStatus)
	}
	sources := make(map[string]string)
	for _, resource := range report.Resources {
		require.NotNil(t, resource.Source)
		path := filepath.ToSlash(resource.Source.RelativePath)
		require.NotContains(t, sources, path, "a source must not be counted twice")
		require.Contains(t, statuses, resource.ResourceID)
		sources[path] = statuses[resource.ResourceID]
	}
	assert.Len(t, report.Results, len(report.Resources))
	return sources
}
