package opaprocessor

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/opa-utils/reporthandling"
)

func TestGetKubernetesObjects(t *testing.T) {
}

var rule_v1_0_131 = &reporthandling.PolicyRule{PortalBase: armotypes.PortalBase{
	Attributes: map[string]interface{}{"useUntilKubescapeVersion": "v1.0.132"}}}
var rule_v1_0_132 = &reporthandling.PolicyRule{PortalBase: armotypes.PortalBase{
	Attributes: map[string]interface{}{"useFromKubescapeVersion": "v1.0.132", "useUntilKubescapeVersion": "v1.0.133"}}}
var rule_v1_0_133 = &reporthandling.PolicyRule{PortalBase: armotypes.PortalBase{
	Attributes: map[string]interface{}{"useFromKubescapeVersion": "v1.0.133", "useUntilKubescapeVersion": "v1.0.134"}}}
var rule_v1_0_134 = &reporthandling.PolicyRule{PortalBase: armotypes.PortalBase{
	Attributes: map[string]interface{}{"useFromKubescapeVersion": "v1.0.134"}}}

func TestIsRuleKubescapeVersionCompatible(t *testing.T) {
	// local build- no build number
	// should use only rules that don't have "until"
	cautils.BuildNumber = ""
	if isRuleKubescapeVersionCompatible(rule_v1_0_131) {
		t.Error("error in isRuleKubescapeVersionCompatible")
	}
	if isRuleKubescapeVersionCompatible(rule_v1_0_132) {
		t.Error("error in isRuleKubescapeVersionCompatible")
	}
	if isRuleKubescapeVersionCompatible(rule_v1_0_133) {
		t.Error("error in isRuleKubescapeVersionCompatible")
	}
	if !isRuleKubescapeVersionCompatible(rule_v1_0_134) {
		t.Error("error in isRuleKubescapeVersionCompatible")
	}

	// should only use rules that version is in range of use
	cautils.BuildNumber = "v1.0.133"
	if isRuleKubescapeVersionCompatible(rule_v1_0_131) {
		t.Error("error in isRuleKubescapeVersionCompatible")
	}
	if isRuleKubescapeVersionCompatible(rule_v1_0_132) {
		t.Error("error in isRuleKubescapeVersionCompatible")
	}
	if !isRuleKubescapeVersionCompatible(rule_v1_0_133) {
		t.Error("error in isRuleKubescapeVersionCompatible")
	}
	if isRuleKubescapeVersionCompatible(rule_v1_0_134) {
		t.Error("error in isRuleKubescapeVersionCompatible")
	}
}

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
