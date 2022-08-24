package cautils

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"golang.org/x/mod/semver"
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
	buildNumberMock := ""
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_131.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_132.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_133.Attributes, buildNumberMock))
	assert.True(t, isRuleKubescapeVersionCompatible(rule_v1_0_134.Attributes, buildNumberMock))

	// should only use rules that version is in range of use
	buildNumberMock = "v1.0.130"
	assert.True(t, isRuleKubescapeVersionCompatible(rule_v1_0_131.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_132.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_133.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_134.Attributes, buildNumberMock))

	// should only use rules that version is in range of use
	buildNumberMock = "v1.0.132"
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_131.Attributes, buildNumberMock))
	assert.True(t, isRuleKubescapeVersionCompatible(rule_v1_0_132.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_133.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_134.Attributes, buildNumberMock))

	// should only use rules that version is in range of use
	buildNumberMock = "v1.0.133"
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_131.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_132.Attributes, buildNumberMock))
	assert.True(t, isRuleKubescapeVersionCompatible(rule_v1_0_133.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_134.Attributes, buildNumberMock))

	// should only use rules that version is in range of use
	buildNumberMock = "v1.0.135"
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_131.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_132.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_133.Attributes, buildNumberMock))
	assert.True(t, isRuleKubescapeVersionCompatible(rule_v1_0_134.Attributes, buildNumberMock))
}

func TestCheckLatestVersion(t *testing.T) {
	assert.Equal(t, -1, semver.Compare("v2.0.150", "v2.0.151"))
	assert.Equal(t, 0, semver.Compare("v2.0.150", "v2.0.150"))
	assert.Equal(t, 1, semver.Compare("v2.0.150", "v2.0.149"))
	assert.Equal(t, -1, semver.Compare("v2.0.150", "v3.0.150"))

}
