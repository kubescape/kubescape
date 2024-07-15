package prettyprinter

import (
	"io"
	"os"
	"testing"

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
}

func TestNewClusterPrinter(t *testing.T) {
	// Test case 1: Valid writer
	cp := NewClusterPrinter(os.Stdout)
	assert.NotNil(t, cp)
	assert.Equal(t, os.Stdout, cp.writer)
	assert.NotNil(t, cp.categoriesTablePrinter)

	// Test case 2: Nil writer
	var writer *os.File
	cp = NewClusterPrinter(writer)
	assert.NotNil(t, cp)
	assert.Nil(t, cp.writer)
	assert.NotNil(t, cp.categoriesTablePrinter)
}

func TestPrintNextSteps(t *testing.T) {
	// Create a temporary file to capture output
	f, err := os.CreateTemp("", "print-next-steps")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	cp := NewClusterPrinter(f)

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
	cp := NewClusterPrinter(os.Stdout)
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
			want:      "$ kubescape scan workload /Empty --namespace ",
		},
		{
			name:      "Empty Namespace",
			namespace: "",
			kind:      "Kind",
			want:      "$ kubescape scan workload Kind/Empty Namespace --namespace ",
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
