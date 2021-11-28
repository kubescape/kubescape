package opaprocessor

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
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
