package opaprocessor

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kubescape/k8s-interface/workloadinterface"
)

func TestRemoveData(t *testing.T) {

	w := `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"demoservice-server"},"spec":{"replicas":1,"selector":{"matchLabels":{"app":"demoservice-server"}},"template":{"metadata":{"creationTimestamp":null,"labels":{"app":"demoservice-server"}},"spec":{"containers":[{"env":[{"name":"SERVER_PORT","value":"8089"},{"name":"SLEEP_DURATION","value":"1"},{"name":"DEMO_FOLDERS","value":"/app"},{"name":"ARMO_TEST_NAME","value":"auto_attach_deployment"},{"name":"CAA_ENABLE_CRASH_REPORTER","value":"1"}],"image":"quay.io/armosec/demoservice:v25","imagePullPolicy":"IfNotPresent","name":"demoservice","ports":[{"containerPort":8089,"protocol":"TCP"}],"resources":{},"terminationMessagePath":"/dev/termination-log","terminationMessagePolicy":"File"}],"dnsPolicy":"ClusterFirst","restartPolicy":"Always","schedulerName":"default-scheduler","securityContext":{},"terminationGracePeriodSeconds":30}}}}`
	obj, _ := workloadinterface.NewWorkload([]byte(w))
	removeData(obj)

	workload := workloadinterface.NewWorkloadObj(obj.GetObject())
	c, _ := workload.GetContainers()
	for i := range c {
		for _, e := range c[i].Env {
			assert.Equal(t, "XXXXXX", e.Value)
		}
	}
}
