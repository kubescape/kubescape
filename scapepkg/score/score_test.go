package score

import (
	"testing"
)

func TestFrameworkMock(t *testing.T) {
	r := getMITREFrameworkResultMock()
	su := NewScore(nil, "")
	var epsilon float32 = 0.001
	su.Calculate(r)
	var sumweights float32 = 0.0
	for _, v := range su.ResourceTypeScores {
		sumweights += v
	}

	for _, framework := range r {
		if framework.Score < 1 {
			t.Errorf("framework %s invalid calculation1: %v", framework.Name, framework)
		}

		if framework.Score > framework.WCSScore+epsilon {
			t.Errorf("framework %s invalid calculation2: %v", framework.Name, framework)
		}
		if framework.ARMOImprovement > framework.Score+epsilon {
			t.Errorf("framework %s invalid calculation3: %v", framework.Name, framework)
		}
		if framework.ControlReports[0].Score*sumweights <= 0+epsilon {
			t.Errorf("framework %s invalid calculation4: %v", framework.Name, framework)
		}
	}
	//
}

func TestDaemonsetRule(t *testing.T) {
	desiredType := "daemonset"
	r := getResouceByType(desiredType)
	if r == nil {
		t.Errorf("no %v was found in the mock, should be 1", desiredType)
	}
	su := NewScore(nil, "")

	resources := []map[string]interface{}{r}
	weights := su.resourceRules(resources)
	expecting := 13 * su.ResourceTypeScores[desiredType]
	if weights != expecting {
		t.Errorf("no %v unexpected weights were calculated expecting: %v got %v", desiredType, expecting, weights)
	}
}

func TestMultipleReplicasRule(t *testing.T) {
	desiredType := "deployment"
	r := getResouceByType(desiredType)
	if r == nil {
		t.Errorf("no %v was found in the mock, should be 1", desiredType)
	}
	su := NewScore(nil, "")

	resources := []map[string]interface{}{r}
	weights := su.resourceRules(resources)
	expecting := 3 * su.ResourceTypeScores[desiredType] * su.ResourceTypeScores["replicaset"]
	if weights != expecting {
		t.Errorf("no %v unexpected weights were calculated expecting: %v got %v", desiredType, expecting, weights)
	}
}
