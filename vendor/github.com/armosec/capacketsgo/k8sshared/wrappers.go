package k8sshared

import (
	"encoding/json"
	"fmt"

	k8saudit "k8s.io/apiserver/pkg/apis/audit"
)

// K8sAuditLog - ARMO audit event wrapper
type K8sAuditLog struct {
	CAClusterName string          `json:"caClusterName"`
	CANamespace   string          `json:"caNamespace"`
	Event         json.RawMessage `json:"k8sV1Event"`
}

//K8sAuditLogs - slice of K8sAuditLog
type K8sAuditLogs []K8sAuditLog

func (v *K8sAuditLog) Validate() bool {
	return len(v.CAClusterName) > 0
}

func (v *K8sAuditLog) GetRawK8sEvent() *k8saudit.Event {
	tmp := &k8saudit.Event{}

	json.Unmarshal(v.Event, &tmp)
	return tmp
}

func Newk8sAuditLog(cluster, namespace string, auditRAW *k8saudit.Event) (*K8sAuditLog, error) {

	audit := &K8sAuditLog{CAClusterName: cluster, CANamespace: namespace}
	b, err := json.Marshal(*auditRAW)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal audit event, reason: %s", err.Error())
	}
	audit.Event = b

	return audit, nil
}
