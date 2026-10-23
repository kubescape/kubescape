package predict

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/pkg/pss"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func namespaceIdentityPod(namespace string, privileged bool) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "shared", "namespace": namespace},
		"spec": map[string]any{
			"containers": []any{map[string]any{
				"name": "main", "image": "example.invalid/app:1",
				"securityContext": map[string]any{"privileged": privileged},
			}},
		},
	}}
}

func namespaceIdentityResult() pss.NamespaceResult {
	return pss.Aggregate("", []unstructured.Unstructured{
		namespaceIdentityPod("zeta", true), namespaceIdentityPod("alpha", false),
	}, pss.Baseline)
}

func TestPSSNamespaceIdentitySurvivesAggregation(t *testing.T) {
	for _, scope := range []string{"", "fallback"} {
		t.Run("scope="+scope, func(t *testing.T) {
			objects := []unstructured.Unstructured{
				namespaceIdentityPod("zeta", true), namespaceIdentityPod("alpha", false),
			}
			before, err := json.Marshal(objects)
			require.NoError(t, err)
			result := pss.Aggregate(scope, objects, pss.Baseline)
			require.Len(t, result.Results, 2)
			require.Equal(t, scope, result.Namespace, "the scan scope is not an individual workload identity")
			require.Equal(t, "alpha", result.Results[0].Namespace)
			require.Equal(t, "zeta", result.Results[1].Namespace)
			require.Equal(t, "zeta", result.FailingResults()[0].Namespace)
			require.Equal(t, "alpha", result.PassingResults()[0].Namespace)
			after, err := json.Marshal(objects)
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
}

func TestPSSNamespaceIdentityDefaultsOnlyWhenAbsent(t *testing.T) {
	for _, tc := range []struct {
		namespace, scope, want string
	}{
		{"", "", ""}, {"", "prod", "prod"},
		{"prod", "", "prod"}, {"actual", "scope", "actual"},
	} {
		t.Run(tc.namespace+"/"+tc.scope, func(t *testing.T) {
			result := pss.Aggregate(tc.scope, []unstructured.Unstructured{
				namespaceIdentityPod(tc.namespace, true),
			}, pss.Baseline)
			require.Len(t, result.Results, 1)
			require.Equal(t, tc.want, result.Results[0].Namespace)
		})
	}
}

func TestPSSNamespaceIdentityJSONAndMCPMap(t *testing.T) {
	result := namespaceIdentityResult()
	var output bytes.Buffer
	require.NoError(t, writeJSON(&output, result))
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(output.Bytes(), &decoded))
	entries := decoded["failing_workloads"].([]any)
	require.Len(t, entries, 1)
	require.Equal(t, "zeta", entries[0].(map[string]any)["namespace"])
	require.Equal(t, "shared", entries[0].(map[string]any)["name"])
	structured := result.ToMap()["failing_workloads"].([]map[string]any)
	require.Len(t, structured, 1)
	require.Equal(t, "zeta", structured[0]["namespace"])
	require.Empty(t, result.ToMap()["namespace"])
}

func TestPSSNamespaceIdentitySARIFLocations(t *testing.T) {
	result := pss.Aggregate("", []unstructured.Unstructured{
		namespaceIdentityPod("zeta", true), namespaceIdentityPod("alpha", true),
	}, pss.Baseline)
	var output bytes.Buffer
	require.NoError(t, writeSARIF(&output, result))
	var report sarifReport
	require.NoError(t, json.Unmarshal(output.Bytes(), &report))
	require.Len(t, report.Runs, 1)
	locations := map[string]bool{}
	for _, finding := range report.Runs[0].Results {
		require.Len(t, finding.Locations, 1)
		logical := finding.Locations[0].LogicalLocations[0]
		locations[logical.FullyQualifiedName] = true
	}
	require.Equal(t, map[string]bool{
		"alpha/Pod/shared/main": true, "zeta/Pod/shared/main": true,
	}, locations, "code scanning must not collapse findings from different namespaces")
}

func TestPSSNamespaceIdentityJUnitDoesNotCollide(t *testing.T) {
	result := namespaceIdentityResult()
	var output bytes.Buffer
	require.NoError(t, writeJUnit(&output, result))
	var report junitTestSuites
	require.NoError(t, xml.Unmarshal(output.Bytes(), &report))
	require.Equal(t, 2, report.Tests)
	require.Equal(t, 1, report.Failures)
	cases := report.TestSuite[0].TestCases
	require.Len(t, cases, 2)
	require.Equal(t, "pss.alpha.Pod", cases[0].ClassName)
	require.Nil(t, cases[0].Failure)
	require.Equal(t, "pss.zeta.Pod", cases[1].ClassName)
	require.NotNil(t, cases[1].Failure)
	require.NotEqual(t, cases[0].ClassName+cases[0].Name, cases[1].ClassName+cases[1].Name)
}

func TestPSSNamespaceIdentityHumanReadableFormats(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func(*bytes.Buffer, pss.NamespaceResult, bool) error
	}{
		{"pretty", func(b *bytes.Buffer, r pss.NamespaceResult, v bool) error { return writePretty(b, r, v) }},
		{"table", func(b *bytes.Buffer, r pss.NamespaceResult, v bool) error { return writeTable(b, r, v) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			require.NoError(t, tc.write(&output, namespaceIdentityResult(), true))
			require.Contains(t, output.String(), "alpha")
			require.Contains(t, output.String(), "zeta")
		})
	}
}

func TestPSSNamespaceIdentityStableAcrossInputOrder(t *testing.T) {
	objects := []unstructured.Unstructured{
		namespaceIdentityPod("zeta", true), namespaceIdentityPod("alpha", true),
	}
	var previous []byte
	for range 2 {
		result := pss.Aggregate("", objects, pss.Baseline)
		var output bytes.Buffer
		require.NoError(t, writeJSON(&output, result))
		if previous != nil {
			require.JSONEq(t, string(previous), output.String())
		}
		previous = slices.Clone(output.Bytes())
		slices.Reverse(objects)
	}
}

func TestPSSNamespaceIdentityWarningsIdentifyMalformedWorkload(t *testing.T) {
	objects := []unstructured.Unstructured{
		namespaceIdentityPod("zeta", true), namespaceIdentityPod("alpha", false),
	}
	for i := range objects {
		delete(objects[i].Object, "spec")
	}
	result := pss.Aggregate("", objects, pss.Baseline)
	require.Equal(t, 2, result.UnevaluatedWorkloads)
	require.Len(t, result.DecodeWarnings, 2)
	require.Contains(t, result.DecodeWarnings[0], "zeta/Pod/shared")
	require.Contains(t, result.DecodeWarnings[1], "alpha/Pod/shared")
}

func TestPSSNamespaceIdentityLocalCommandReport(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "pods.json")
	output := filepath.Join(dir, "report.json")
	var records []string
	for _, ns := range []string{"zeta", "alpha"} {
		raw, err := json.Marshal(namespaceIdentityPod(ns, true).Object)
		require.NoError(t, err)
		records = append(records, string(raw))
	}
	require.NoError(t, os.WriteFile(input, []byte(strings.Join(records, "\n")), 0o600))
	err := runPSS(context.Background(), &pssFlags{level: "Baseline", format: "json", output: output}, []string{input})
	require.ErrorContains(t, err, "2/2 workload(s)")
	raw, err := os.ReadFile(output)
	require.NoError(t, err)
	var report map[string]any
	require.NoError(t, json.Unmarshal(raw, &report))
	failures := report["failing_workloads"].([]any)
	require.Len(t, failures, 2)
	require.Equal(t, "alpha", failures[0].(map[string]any)["namespace"])
	require.Equal(t, "zeta", failures[1].(map[string]any)["namespace"])
}

func TestPSSNamespaceIdentityLegacyResultFallback(t *testing.T) {
	// Embedders may construct WorkloadResult without Namespace. Preserve the
	// existing single-namespace report identity in every structured formatter.
	result := sampleResult()
	var output bytes.Buffer
	require.NoError(t, writeJSON(&output, result))
	var jsonReport map[string]any
	require.NoError(t, json.Unmarshal(output.Bytes(), &jsonReport))
	entry := jsonReport["failing_workloads"].([]any)[0].(map[string]any)
	require.Equal(t, "test-ns", entry["namespace"])
	output.Reset()
	require.NoError(t, writeSARIF(&output, result))
	var sarif sarifReport
	require.NoError(t, json.Unmarshal(output.Bytes(), &sarif))
	require.Equal(t, "test-ns/Deployment/failing-app/main",
		sarif.Runs[0].Results[0].Locations[0].LogicalLocations[0].FullyQualifiedName)
	output.Reset()
	require.NoError(t, writeJUnit(&output, result))
	var junit junitTestSuites
	require.NoError(t, xml.Unmarshal(output.Bytes(), &junit))
	require.Equal(t, "pss.test-ns.Deployment", junit.TestSuite[0].TestCases[0].ClassName)
}

func TestPSSNamespaceIdentityDoesNotInventDefaultNamespace(t *testing.T) {
	result := pss.Aggregate("", []unstructured.Unstructured{namespaceIdentityPod("", true)}, pss.Baseline)
	require.Len(t, result.Results, 1)
	require.Empty(t, result.Results[0].Namespace)
	var output bytes.Buffer
	require.NoError(t, writeSARIF(&output, result))
	var report sarifReport
	require.NoError(t, json.Unmarshal(output.Bytes(), &report))
	require.Equal(t, "Pod/shared/main", report.Runs[0].Results[0].Locations[0].LogicalLocations[0].FullyQualifiedName)
	output.Reset()
	require.NoError(t, writeJUnit(&output, result))
	var junit junitTestSuites
	require.NoError(t, xml.Unmarshal(output.Bytes(), &junit))
	require.Equal(t, "pss.local.Pod", junit.TestSuite[0].TestCases[0].ClassName)
}
