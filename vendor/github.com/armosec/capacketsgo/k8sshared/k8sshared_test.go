package k8sshared

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/armosec/capacketsgo/cautils"
)

func TestAuditStructure(t *testing.T) {
	auditRAW, err := GetK8sAuditEventMock()

	if err != nil {
		t.Errorf("failed to get unmarshald mock %v", err.Error())
	}

	audit, err := Newk8sAuditLog("testcluster", "", &auditRAW)
	if err != nil {
		t.Errorf("failed to create ca-k8s-audit object due to : %v", err.Error())
	}

	res, err := json.Marshal(audit)
	if err != nil {
		t.Errorf("failed to get marshal audit wrapper %v", err.Error())
	}

	fmt.Printf("\n\nres: %v\n\n", string(res))

	audit2 := K8sAuditLog{}

	json.Unmarshal(res, &audit2)

	if cautils.AsSHA256(audit2) != cautils.AsSHA256(*audit) {
		t.Errorf("failed to get umarshal(marshal audit wrapper)\n========audit2=======\n%v\n\noriginal:\n:%v", audit2, audit)
	}

	auditRAW2 := audit2.GetRawK8sEvent()

	if cautils.AsSHA256(*auditRAW2) != cautils.AsSHA256(auditRAW) {
		t.Errorf("failed to get raw audit is different from k8s original audit:\nreplacement:\n%v\n\noriginal: %v", *auditRAW2, auditRAW)
	}

}
