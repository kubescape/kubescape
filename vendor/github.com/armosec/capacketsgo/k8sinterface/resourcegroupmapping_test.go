package k8sinterface

import "testing"

func TestResourceGroupToString(t *testing.T) {
	allResources := ResourceGroupToString("*", "*", "*")
	if len(allResources) != len(ResourceGroupMapping) {
		t.Errorf("Expected len: %d, received: %d", len(ResourceGroupMapping), len(allResources))
	}
	pod := ResourceGroupToString("*", "*", "Pod")
	if len(pod) == 0 || pod[0] != "/v1/pods" {
		t.Errorf("pod: %v", pod)
	}
	deployments := ResourceGroupToString("*", "*", "Deployment")
	if len(deployments) == 0 || deployments[0] != "apps/v1/deployments" {
		t.Errorf("deployments: %v", deployments)
	}
	cronjobs := ResourceGroupToString("*", "*", "cronjobs")
	if len(cronjobs) == 0 || cronjobs[0] != "batch/v1beta1/cronjobs" {
		t.Errorf("cronjobs: %v", cronjobs)
	}
}
