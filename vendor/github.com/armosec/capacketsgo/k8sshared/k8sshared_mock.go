package k8sshared

import (
	"encoding/json"

	audit "k8s.io/apiserver/pkg/apis/audit"
)

func GetEventAuditMockAsString() string {
	return `{
	"kind": "Event",
	"apiVersion": "audit.k8s.io/v1",
	"level": "Metadata",
	"auditID": "1847e1e1-d66b-4661-b458-4dc553cd8539",
	"stage": "ResponseComplete",
	"requestURI": "/apis/storage.k8s.io/v1?timeout=32s",
	"verb": "get",
	"user": {
		"username": "system:serviceaccount:kube-system:generic-garbage-collector",
		"uid": "83093a4c-3f5f-433e-8fd4-4a2cc23eead8",
		"groups": [
			"system:serviceaccounts",
			"system:serviceaccounts:kube-system",
			"system:authenticated"
		]
	},
	"sourceIPs": [
		"192.168.49.2"
	],
	"userAgent": "kube-controller-manager/v1.20.0 (linux/amd64) kubernetes/af46c47/system:serviceaccount:kube-system:generic-garbage-collector",
	"responseStatus": {
		"metadata": {},
		"code": 200
	},
	"requestReceivedTimestamp": "2021-02-18T08:28:43.237861Z",
	"stageTimestamp": "2021-02-18T08:28:43.238551Z",
	"annotations": {
		"authentication.k8s.io/legacy-token": "system:serviceaccount:kube-system:generic-garbage-collector",
		"authorization.k8s.io/decision": "allow",
		"authorization.k8s.io/reason": "RBAC: allowed by ClusterRoleBinding \"system:discovery\" of ClusterRole \"system:discovery\" to Group \"system:authenticated\""
	}
}`
}

func GetK8sAuditEventMock() (audit.Event, error) {
	tmp := audit.Event{}
	a := []byte(GetEventAuditMockAsString())
	err := json.Unmarshal(a, &tmp)

	return tmp, err
}
