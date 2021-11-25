package opaprocessor

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/opa-utils/reporthandling"
	"github.com/armosec/opa-utils/resources"

	"github.com/armosec/k8s-interface/k8sinterface"
	// _ "k8s.io/client-go/plugin/pkg/client/auth"
)

func NewOPAProcessorMock() *OPAProcessor {
	return &OPAProcessor{}
}
func TestProcess(t *testing.T) {

	// set k8s
	k8sResources := make(cautils.K8SResources)
	k8sResources["/v1/pods"] = k8sinterface.ConvertUnstructuredSliceToMap(k8sinterface.V1KubeSystemNamespaceMock().Items)

	// set opaSessionObj
	opaSessionObj := cautils.NewOPASessionObjMock()
	opaSessionObj.Frameworks = []reporthandling.Framework{*reporthandling.MockFrameworkA()}
	opaSessionObj.K8SResources = &k8sResources

	opap := NewOPAProcessor(opaSessionObj, resources.NewRegoDependenciesDataMock())
	opap.Process()
	opap.updateResults()
	for _, f := range opap.PostureReport.FrameworkReports {
		for _, c := range f.ControlReports {
			for _, r := range c.RuleReports {
				for _, rr := range r.RuleResponses {
					// t.Errorf("AlertMessage: %v", rr.AlertMessage)
					if rr.Exception != nil {
						t.Errorf("Exception: %v", rr.Exception)
					}
				}
			}
		}
	}

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
