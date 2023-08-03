package prettyprinter

import "testing"

func TestWorkloadScan_getNextSteps(t *testing.T) {
	workloadPrinter := &WorkloadPrinter{}

	nextSteps := workloadPrinter.getNextSteps()

	if len(nextSteps) != 3 {
		t.Errorf("Expected 3 next steps, got %d", len(nextSteps))
	}

	if nextSteps[0] != configScanVerboseRunText {
		t.Errorf("Expected %s, got %s", configScanVerboseRunText, nextSteps[0])
	}

	if nextSteps[1] != installHelmText {
		t.Errorf("Expected %s, got %s", installHelmText, nextSteps[1])
	}

	if nextSteps[2] != CICDSetupText {
		t.Errorf("Expected %s, got %s", CICDSetupText, nextSteps[2])
	}
}
