package prettyprinter

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepoScan_getNextSteps(t *testing.T) {
	repoPrinter := &RepoPrinter{}

	nextSteps := repoPrinter.getNextSteps()

	if len(nextSteps) != 4 {
		t.Errorf("Expected 4 next steps, got %d", len(nextSteps))
	}

	if nextSteps[0] != runCommandsText {
		t.Errorf("Expected %s, got %s", clusterScanRunText, nextSteps[0])
	}

	if nextSteps[1] != clusterScanRunText {
		t.Errorf("Expected %s, got %s", runCommandsText, nextSteps[1])
	}

	if nextSteps[2] != scanWorkloadText {
		t.Errorf("Expected %s, got %s", scanWorkloadText, nextSteps[2])
	}

	if nextSteps[3] != installKubescapeText {
		t.Errorf("Expected %s, got %s", installKubescapeText, nextSteps[3])
	}
}

func TestRepoScan_getWorkloadScanCommand(t *testing.T) {
	test := []struct {
		testName string
		ns       string
		kind     string
		name     string
		source   *reporthandling.Source
		want     string
	}{
		{
			testName: "file path",
			ns:       "ns",
			kind:     "kind",
			name:     "name",
			source: &reporthandling.Source{
				Path:         "path",
				RelativePath: "relativePath",
			},
			want: "$ kubescape scan workload kind/name --namespace ns --file-path=" + filepath.Join("path", "relativePath"),
		},
		{
			testName: "relative file path",
			ns:       "ns",
			kind:     "kind",
			name:     "name",
			source: &reporthandling.Source{
				Path:         "",
				RelativePath: "relativePath",
			},
			want: "$ kubescape scan workload kind/name --namespace ns --file-path=relativePath",
		},
		{
			testName: "helm path",
			ns:       "ns",
			kind:     "kind",
			name:     "name",
			source: &reporthandling.Source{
				Path:         "path",
				RelativePath: "relativePath",
				HelmPath:     "helmPath",
				FileType:     "Helm Chart",
			},
			want: "$ kubescape scan workload kind/name --namespace ns --chart-path=helmPath --file-path=" + filepath.Join("path", "relativePath"),
		},
		{
			testName: "file path - no namespace",
			kind:     "kind",
			name:     "name",
			source: &reporthandling.Source{
				Path:         "path",
				RelativePath: "relativePath",
			},
			want: "$ kubescape scan workload kind/name --file-path=" + filepath.Join("path", "relativePath"),
		},
		{
			testName: "helm path - no namespace",
			kind:     "kind",
			name:     "name",
			source: &reporthandling.Source{
				Path:         "path",
				RelativePath: "relativePath",
				HelmPath:     "helmPath",
				FileType:     "Helm Chart",
			},
			want: "$ kubescape scan workload kind/name --chart-path=helmPath --file-path=" + filepath.Join("path", "relativePath"),
		},
		{
			testName: "nil source",
			ns:       "ns",
			kind:     "kind",
			name:     "name",
			source:   nil,
			want:     "$ kubescape scan workload kind/name --namespace ns",
		},
		{
			testName: "empty source paths",
			ns:       "ns",
			kind:     "kind",
			name:     "name",
			source:   &reporthandling.Source{},
			want:     "$ kubescape scan workload kind/name --namespace ns",
		},
		{
			testName: "helm chart without file path",
			ns:       "ns",
			kind:     "kind",
			name:     "name",
			source: &reporthandling.Source{
				HelmPath: "helmPath",
				FileType: "Helm Chart",
			},
			want: "$ kubescape scan workload kind/name --namespace ns --chart-path=helmPath",
		},
	}

	for _, tt := range test {
		t.Run(tt.testName, func(t *testing.T) {
			repoPrinter := &RepoPrinter{}

			if got := repoPrinter.getWorkloadScanCommand(tt.ns, tt.kind, tt.name, tt.source); got != tt.want {
				t.Errorf("in test %s failed, got = %v, want %v", tt.testName, got, tt.want)
			}
		})
	}

}

// TestRepoScan_printTopWorkloads_ResourceNameWithPercentVerbs guards against a
// regression where resource-derived text was passed as the format argument to
// cautils.SimpleDisplay instead of as a %s value: a resource name containing
// %-verbs (reachable from an untrusted scanned manifest) was silently
// corrupted by fmt's format-string interpretation instead of being printed
// literally.
func TestRepoScan_printTopWorkloads_ResourceNameWithPercentVerbs(t *testing.T) {
	f, err := os.CreateTemp("", "print-top-workloads")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	rp := &RepoPrinter{writer: f}

	name := "my-deployment-%s-%d-leaked"
	resource := reporthandling.NewResource(map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": "default",
		},
	})
	resource.SetSource(&reporthandling.Source{Path: "path", RelativePath: "relativePath"})

	rp.printTopWorkloads([]reporthandling.IResource{resource})

	f.Seek(0, 0)
	got, err := io.ReadAll(f)
	if err != nil {
		panic(err)
	}

	assert.Contains(t, string(got), name, "resource name must be printed literally, not interpreted as a format string")
}

func TestRepoScan_printTopWorkloads_NilSourceDoesNotPanic(t *testing.T) {
	f, err := os.CreateTemp("", "print-top-workloads-nil-source")
	require.NoError(t, err)
	defer f.Close()

	rp := &RepoPrinter{writer: f}

	resource := reporthandling.NewResource(map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]interface{}{
			"name":      "deploy-no-source",
			"namespace": "prod",
		},
	})
	// Explicitly leave source as nil to verify no nil pointer dereference
	assert.Nil(t, resource.GetSource())

	assert.NotPanics(t, func() {
		rp.printTopWorkloads([]reporthandling.IResource{resource})
	})

	_, err = f.Seek(0, 0)
	require.NoError(t, err)
	got, err := io.ReadAll(f)
	require.NoError(t, err)

	assert.Contains(t, string(got), "deploy-no-source")
	assert.Contains(t, string(got), "$ kubescape scan workload Deployment/deploy-no-source --namespace prod")
}

func TestRepoScan_printTopWorkloads_NilWorkloadInSliceSkipped(t *testing.T) {
	f, err := os.CreateTemp("", "print-top-workloads-nil-wl")
	require.NoError(t, err)
	defer f.Close()

	rp := &RepoPrinter{writer: f}

	resource := reporthandling.NewResource(map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]interface{}{
			"name":      "valid-deploy",
			"namespace": "default",
		},
	})

	assert.NotPanics(t, func() {
		rp.printTopWorkloads([]reporthandling.IResource{nil, resource, nil})
	})

	_, err = f.Seek(0, 0)
	require.NoError(t, err)
	got, err := io.ReadAll(f)
	require.NoError(t, err)

	assert.Contains(t, string(got), "valid-deploy")
}

func TestRepoScan_PrintConfigurationsScanning_SingleTopWorkloadRendered(t *testing.T) {
	f, err := os.CreateTemp("", "print-config-single-wl")
	require.NoError(t, err)
	defer f.Close()

	rp := NewRepoPrinter(f, []string{"."}, false)

	resource := reporthandling.NewResource(map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]interface{}{
			"name":      "single-top-workload",
			"namespace": "default",
		},
	})
	resource.SetSource(&reporthandling.Source{Path: "manifests", RelativePath: "deploy.yaml"})

	summaryDetails := &reportsummary.SummaryDetails{}
	rp.PrintConfigurationsScanning(summaryDetails, nil, []reporthandling.IResource{resource})

	_, err = f.Seek(0, 0)
	require.NoError(t, err)
	got, err := io.ReadAll(f)
	require.NoError(t, err)

	assert.Contains(t, string(got), "Highest-stake workloads")
	assert.Contains(t, string(got), "single-top-workload")
	assert.Contains(t, string(got), "$ kubescape scan workload Deployment/single-top-workload --namespace default --file-path="+filepath.Join("manifests", "deploy.yaml"))
}

func TestRepoScan_PrintConfigurationsScanning_EmptyTopWorkloadsNotRendered(t *testing.T) {
	f, err := os.CreateTemp("", "print-config-empty-wl")
	require.NoError(t, err)
	defer f.Close()

	rp := NewRepoPrinter(f, []string{"."}, false)

	summaryDetails := &reportsummary.SummaryDetails{}
	rp.PrintConfigurationsScanning(summaryDetails, nil, []reporthandling.IResource{})

	_, err = f.Seek(0, 0)
	require.NoError(t, err)
	got, err := io.ReadAll(f)
	require.NoError(t, err)

	assert.NotContains(t, string(got), "Highest-stake workloads")
}
