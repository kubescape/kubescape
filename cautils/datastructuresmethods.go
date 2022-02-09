package cautils

import (
	pkgcautils "github.com/armosec/utils-go/utils"

	"github.com/armosec/opa-utils/reporthandling"
)

func NewPolicies() *Policies {
	return &Policies{
		Frameworks: make([]string, 0),
		Controls:   make(map[string]reporthandling.Control),
	}
}

func (policies *Policies) Set(frameworks []reporthandling.Framework, version string) {
	for i := range frameworks {
		if frameworks[i].Name != "" {
			policies.Frameworks = append(policies.Frameworks, frameworks[i].Name)
		}
		for j := range frameworks[i].Controls {
			compatibleRules := []reporthandling.PolicyRule{}
			for r := range frameworks[i].Controls[j].Rules {
				if !ruleWithArmoOpaDependency(frameworks[i].Controls[j].Rules[r].Attributes) && isRuleKubescapeVersionCompatible(frameworks[i].Controls[j].Rules[r].Attributes, version) {
					compatibleRules = append(compatibleRules, frameworks[i].Controls[j].Rules[r])
				}
			}
			if len(compatibleRules) > 0 {
				frameworks[i].Controls[j].Rules = compatibleRules
				policies.Controls[frameworks[i].Controls[j].ControlID] = frameworks[i].Controls[j]
			}
		}
	}
}

func ruleWithArmoOpaDependency(attributes map[string]interface{}) bool {
	if attributes == nil {
		return false
	}
	if s, ok := attributes["armoOpa"]; ok { // TODO - make global
		return pkgcautils.StringToBool(s.(string))
	}
	return false
}

// Checks that kubescape version is in range of use for this rule
// In local build (BuildNumber = ""):
// returns true only if rule doesn't have the "until" attribute
func isRuleKubescapeVersionCompatible(attributes map[string]interface{}, version string) bool {
	if from, ok := attributes["useFromKubescapeVersion"]; ok && from != nil {
		if version != "" {
			if from.(string) > BuildNumber {
				return false
			}
		}
	}
	if until, ok := attributes["useUntilKubescapeVersion"]; ok && until != nil {
		if version != "" {
			if until.(string) <= BuildNumber {
				return false
			}
		} else {
			return false
		}
	}
	return true
}
