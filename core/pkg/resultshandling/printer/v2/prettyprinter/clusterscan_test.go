package prettyprinter

import (
	"io"
	"os"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
)

func TestClusterScan_getNextSteps(t *testing.T) {
	clusterPrinter := &ClusterPrinter{}

	nextSteps := clusterPrinter.getNextSteps()

	if len(nextSteps) != 3 {
		t.Errorf("Expected 3 next steps, got %d", len(nextSteps))
	}

	if nextSteps[0] != runCommandsText {
		t.Errorf("Expected %s, got %s", configScanVerboseRunText, nextSteps[0])
	}

	if nextSteps[1] != scanWorkloadText {
		t.Errorf("Expected %s, got %s", scanWorkloadText, nextSteps[1])
	}

	if nextSteps[2] != installKubescapeText {
		t.Errorf("Expected %s, got %s", installKubescapeText, nextSteps[2])
	}
}

func TestClusterScan_getWorkloadScanCommand(t *testing.T) {
	clusterPrinter := &ClusterPrinter{}

	command := clusterPrinter.getWorkloadScanCommand("ns", "kind", "name")

	if command != "$ kubescape scan workload kind/name --namespace ns" {
		t.Errorf("Expected $ kubescape scan workload kind/name --namespace ns, got %s", command)
	}

	commandNoNs := clusterPrinter.getWorkloadScanCommand("", "ClusterRole", "cluster-admin")
	if commandNoNs != "$ kubescape scan workload ClusterRole/cluster-admin" {
		t.Errorf("Expected $ kubescape scan workload ClusterRole/cluster-admin, got %s", commandNoNs)
	}
}

func TestNewClusterPrinter(t *testing.T) {
	// Test case 1: Valid writer
	cp := NewClusterPrinter(os.Stdout, false)
	assert.NotNil(t, cp)
	assert.Equal(t, os.Stdout, cp.writer)
	assert.NotNil(t, cp.categoriesTablePrinter)
	assert.NotNil(t, cp.imageTablePrinter)
	assert.False(t, cp.verboseMode)

	// Test case 2: Nil writer
	var writer *os.File
	cp = NewClusterPrinter(writer, true)
	assert.NotNil(t, cp)
	assert.Nil(t, cp.writer)
	assert.NotNil(t, cp.categoriesTablePrinter)
	assert.NotNil(t, cp.imageTablePrinter)
	assert.True(t, cp.verboseMode)
}

func TestPrintNextSteps(t *testing.T) {
	// Create a temporary file to capture output
	f, err := os.CreateTemp("", "print-next-steps")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	cp := NewClusterPrinter(f, false)

	// Redirect stderr to the temporary file
	oldStderr := os.Stderr
	defer func() {
		os.Stderr = oldStderr
	}()
	os.Stderr = f

	// Print the score using the `Score` function
	cp.PrintNextSteps()

	// Read the contents of the temporary file
	f.Seek(0, 0)
	got, err := io.ReadAll(f)
	if err != nil {
		panic(err)
	}

	want := "\nWhat now?\n─────────\n\n* Run one of the suggested commands to learn more about a failed control failure\n* Scan a workload with '$ kubescape scan workload' to see vulnerability information\n* Install Kubescape in your cluster for continuous monitoring and a full vulnerability report: https://kubescape.io/docs/install-operator/\n\n"

	assert.Equal(t, want, string(got))
}

func TestGetWorkloadScanCommand(t *testing.T) {
	cp := NewClusterPrinter(os.Stdout, false)
	assert.NotNil(t, cp)
	assert.Equal(t, os.Stdout, cp.writer)
	assert.NotNil(t, cp.categoriesTablePrinter)

	tests := []struct {
		name      string
		namespace string
		kind      string
		want      string
	}{
		{
			name:      "Empty",
			namespace: "",
			kind:      "",
			want:      "$ kubescape scan workload /Empty",
		},
		{
			name:      "Empty Namespace",
			namespace: "",
			kind:      "Kind",
			want:      "$ kubescape scan workload Kind/Empty Namespace",
		},
		{
			name:      "Empty Kind",
			namespace: "Namespace",
			kind:      "",
			want:      "$ kubescape scan workload /Empty Kind --namespace Namespace",
		},
		{
			name:      "Name",
			namespace: "Namespace",
			kind:      "Kind",
			want:      "$ kubescape scan workload Kind/Name --namespace Namespace",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cp.getWorkloadScanCommand(tt.namespace, tt.kind, tt.name)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestClusterScan_printTopWorkloads_ResourceNameWithPercentVerbs guards
// against a regression where resource-derived text was passed as the format
// argument to cautils.SimpleDisplay instead of as a %s value: a resource name
// containing %-verbs (reachable from an untrusted scanned manifest) was
// silently corrupted by fmt's format-string interpretation instead of being
// printed literally.
func TestClusterScan_printTopWorkloads_ResourceNameWithPercentVerbs(t *testing.T) {
	f, err := os.CreateTemp("", "print-top-workloads")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	cp := &ClusterPrinter{writer: f}

	name := "my-deployment-%s-%d-leaked"
	resource := reporthandling.NewResource(map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": "default",
		},
	})

	cp.printTopWorkloads([]reporthandling.IResource{resource})

	f.Seek(0, 0)
	got, err := io.ReadAll(f)
	if err != nil {
		panic(err)
	}

	assert.Contains(t, string(got), name, "resource name must be printed literally, not interpreted as a format string")
}

func TestClusterScan_printTopWorkloads_ClusterScopedResource(t *testing.T) {
	f, err := os.CreateTemp("", "print-top-workloads-clusterscoped")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	cp := &ClusterPrinter{writer: f}

	resource := reporthandling.NewResource(map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata": map[string]interface{}{
			"name": "cluster-admin",
		},
	})

	cp.printTopWorkloads([]reporthandling.IResource{resource})

	f.Seek(0, 0)
	gotBytes, err := io.ReadAll(f)
	if err != nil {
		panic(err)
	}
	got := string(gotBytes)

	assert.Contains(t, got, "1. name: cluster-admin, kind: ClusterRole")
	assert.NotContains(t, got, "namespace:")
	assert.Contains(t, got, "$ kubescape scan workload ClusterRole/cluster-admin")
	assert.NotContains(t, got, "--namespace")
}

func TestSubPrinters_NilReceiverAndNilWriterSafety(t *testing.T) {
	t.Run("ClusterPrinter", func(t *testing.T) {
		var cp *ClusterPrinter
		assert.NotPanics(t, func() {
			cp.PrintNextSteps()
			cp.PrintImageScanning(nil)
			cp.PrintConfigurationsScanning(nil, nil, nil)
		})

		cp2 := NewClusterPrinter(nil, false)
		assert.NotPanics(t, func() {
			cp2.PrintNextSteps()
			cp2.PrintImageScanning(nil)
			cp2.PrintConfigurationsScanning(nil, nil, nil)
		})
	})

	t.Run("SummaryPrinter", func(t *testing.T) {
		var sp *SummaryPrinter
		assert.NotPanics(t, func() {
			sp.PrintNextSteps()
			sp.PrintImageScanning(nil)
			sp.PrintConfigurationsScanning(nil, nil, nil)
			_ = sp.getVerboseMode()
		})

		sp2 := NewSummaryPrinter(nil, false)
		assert.NotPanics(t, func() {
			sp2.PrintNextSteps()
			sp2.PrintImageScanning(nil)
			sp2.PrintConfigurationsScanning(nil, nil, nil)
			_ = sp2.getVerboseMode()
		})
	})

	t.Run("ImagePrinter", func(t *testing.T) {
		var ip *ImagePrinter
		assert.NotPanics(t, func() {
			ip.PrintNextSteps()
			ip.PrintImageScanning(nil)
			ip.PrintConfigurationsScanning(nil, nil, nil)
		})

		ip2 := NewImagePrinter(nil, false)
		assert.NotPanics(t, func() {
			ip2.PrintNextSteps()
			ip2.PrintImageScanning(nil)
			ip2.PrintConfigurationsScanning(nil, nil, nil)
		})
	})

	t.Run("RepoPrinter", func(t *testing.T) {
		var rp *RepoPrinter
		assert.NotPanics(t, func() {
			rp.PrintNextSteps()
			rp.PrintImageScanning(nil)
			rp.PrintConfigurationsScanning(nil, nil, nil)
		})

		rp2 := NewRepoPrinter(nil, nil, false)
		assert.NotPanics(t, func() {
			rp2.PrintNextSteps()
			rp2.PrintImageScanning(nil)
			rp2.PrintConfigurationsScanning(nil, nil, nil)
		})
	})

	t.Run("WorkloadPrinter", func(t *testing.T) {
		var wp *WorkloadPrinter
		assert.NotPanics(t, func() {
			wp.PrintNextSteps()
			wp.PrintImageScanning(nil)
			wp.PrintConfigurationsScanning(nil, nil, nil)
		})

		wp2 := NewWorkloadPrinter(nil, false)
		assert.NotPanics(t, func() {
			wp2.PrintNextSteps()
			wp2.PrintImageScanning(nil)
			wp2.PrintConfigurationsScanning(nil, nil, nil)
		})
	})
}
