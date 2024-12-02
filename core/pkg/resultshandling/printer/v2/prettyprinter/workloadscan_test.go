package prettyprinter

import "testing"

func TestWorkloadScan_getNextSteps(t *testing.T) {
	workloadPrinter := &WorkloadPrinter{}

	nextSteps := workloadPrinter.getNextSteps()

	if len(nextSteps) != 3 {
		t.Errorf("Expected 3 next steps, got %d", len(nextSteps))
	}

	if nextSteps[0] != runCommandsText {
		t.Errorf("Expected %s, got %s", runCommandsText, nextSteps[0])
	}

	if nextSteps[1] != configScanVerboseRunText {
		t.Errorf("Expected %s, got %s", configScanVerboseRunText, nextSteps[0])
	}

	if nextSteps[2] != installKubescapeText {
		t.Errorf("Expected %s, got %s", installKubescapeText, nextSteps[1])
	}

}
