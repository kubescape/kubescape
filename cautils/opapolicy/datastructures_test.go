package opapolicy

import (
	"encoding/json"
	"testing"
)

func TestMockPolicyNotificationA(t *testing.T) {
	policy := MockPolicyNotificationA()
	bp, err := json.Marshal(policy)
	if err != nil {
		t.Error(err)
	} else {
		t.Logf("%s\n", string(bp))
		// t.Errorf("%s\n", string(bp))
	}

}

func TestMockFrameworkA(t *testing.T) {
	policy := MockFrameworkA()
	bp, err := json.Marshal(policy)
	if err != nil {
		t.Error(err)
	} else {
		t.Logf("%s\n", string(bp))
		// t.Errorf("%s\n", string(bp))
	}

}

func TestMockPostureReportA(t *testing.T) {
	policy := MockPostureReportA()
	bp, err := json.Marshal(policy)
	if err != nil {
		t.Error(err)
	} else {
		// t.Errorf("%s\n", string(bp))
		t.Logf("%s\n", string(bp))
	}

}
