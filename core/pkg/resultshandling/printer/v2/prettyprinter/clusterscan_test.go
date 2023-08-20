package prettyprinter

import "testing"

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
