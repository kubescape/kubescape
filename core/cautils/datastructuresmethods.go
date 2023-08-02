package cautils

import (
	"golang.org/x/mod/semver"

	"github.com/armosec/utils-go/boolutils"
	cloudsupport "github.com/kubescape/k8s-interface/cloudsupport/v1"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
)

func NewPolicies() *Policies {
	return &Policies{
		Frameworks: make([]string, 0),
		Controls:   make(map[string]reporthandling.Control),
	}
}

func (policies *Policies) Set(frameworks []reporthandling.Framework, version string, scanningScope reporthandling.ScanningScopeType) {
	for i := range frameworks {
		if frameworks[i].Name != "" && len(frameworks[i].Controls) > 0 && isFrameworkFitToScanScope(frameworks[i], scanningScope) {
			policies.Frameworks = append(policies.Frameworks, frameworks[i].Name)
		} else {
			continue
		}
		for j := range frameworks[i].Controls {
			compatibleRules := []reporthandling.PolicyRule{}
			for r := range frameworks[i].Controls[j].Rules {
				if !ruleWithKSOpaDependency(frameworks[i].Controls[j].Rules[r].Attributes) && isRuleKubescapeVersionCompatible(frameworks[i].Controls[j].Rules[r].Attributes, version) && isControlFitToScanScope(frameworks[i].Controls[j], scanningScope) {
					compatibleRules = append(compatibleRules, frameworks[i].Controls[j].Rules[r])
				}
			}
			if len(compatibleRules) > 0 {
				frameworks[i].Controls[j].Rules = compatibleRules
				policies.Controls[frameworks[i].Controls[j].ControlID] = frameworks[i].Controls[j]
			} else { // if the control type is manual review, add it to the list of controls
				actionRequiredStr := frameworks[i].Controls[j].GetActionRequiredAttribute()
				if actionRequiredStr == "" {
					continue
				}
				if actionRequiredStr == string(apis.SubStatusManualReview) {
					policies.Controls[frameworks[i].Controls[j].ControlID] = frameworks[i].Controls[j]
				}
			}

		}

	}
}

func ruleWithKSOpaDependency(attributes map[string]interface{}) bool {
	if attributes == nil {
		return false
	}
	if s, ok := attributes["armoOpa"]; ok { // TODO - make global
		return boolutils.StringToBool(s.(string))
	}
	return false
}

// Checks that kubescape version is in range of use for this rule
// In local build (BuildNumber = ""):
// returns true only if rule doesn't have the "until" attribute
func isRuleKubescapeVersionCompatible(attributes map[string]interface{}, version string) bool {
	if from, ok := attributes["useFromKubescapeVersion"]; ok && from != nil {
		if version != "" {
			if semver.Compare(version, from.(string)) == -1 {
				return false
			}
		}
	}
	if until, ok := attributes["useUntilKubescapeVersion"]; ok && until != nil {
		if version == "" {
			return false
		}
		if semver.Compare(version, until.(string)) >= 0 {
			return false
		}
	}
	return true
}

func getCloudType(scanInfo *ScanInfo) (bool, reporthandling.ScanningScopeType) {
	if cloudsupport.IsAKS() {
		return true, reporthandling.ScopeCloudAKS
	}
	if cloudsupport.IsEKS(k8sinterface.GetConfig()) {
		return true, reporthandling.ScopeCloudEKS
	}
	if cloudsupport.IsGKE(k8sinterface.GetConfig()) {
		return true, reporthandling.ScopeCloudGKE
	}
	return false, ""
}

func GetScanningScope(scanInfo *ScanInfo) reporthandling.ScanningScopeType {
	var result reporthandling.ScanningScopeType

	switch scanInfo.GetScanningContext() {
	case ContextCluster:
		isCloud, cloudType := getCloudType(scanInfo)
		if isCloud {
			result = cloudType
		} else {
			result = reporthandling.ScopeCluster
		}
	default:
		result = reporthandling.ScopeFile
	}

	return result
}

func isScanningScopeMatchToControlScope(scanScope reporthandling.ScanningScopeType, controlScope reporthandling.ScanningScopeType) bool {
	result := false

	switch controlScope {
	case reporthandling.ScopeFile:
		result = (reporthandling.ScopeFile == scanScope)
	case reporthandling.ScopeCluster:
		result = (reporthandling.ScopeCluster == scanScope) || (reporthandling.ScopeCloud == scanScope) || (reporthandling.ScopeCloudAKS == scanScope) || (reporthandling.ScopeCloudEKS == scanScope) || (reporthandling.ScopeCloudGKE == scanScope)
	case reporthandling.ScopeCloud:
		result = (reporthandling.ScopeCloud == scanScope) || (reporthandling.ScopeCloudAKS == scanScope) || (reporthandling.ScopeCloudEKS == scanScope) || (reporthandling.ScopeCloudGKE == scanScope)
	case reporthandling.ScopeCloudAKS:
		result = (reporthandling.ScopeCloudAKS == scanScope)
	case reporthandling.ScopeCloudEKS:
		result = (reporthandling.ScopeCloudEKS == scanScope)
	case reporthandling.ScopeCloudGKE:
		result = (reporthandling.ScopeCloudGKE == scanScope)
	default:
		result = true
	}

	return result
}

func isControlFitToScanScope(control reporthandling.Control, scanScopeMatches reporthandling.ScanningScopeType) bool {
	// for backward compatibility - case: kubescape with scope(new one) and regolibrary without scope(old one)
	if control.ScanningScope == nil {
		return true
	}
	if len(control.ScanningScope.Matches) == 0 {
		return true
	}
	for i := range control.ScanningScope.Matches {
		if isScanningScopeMatchToControlScope(scanScopeMatches, control.ScanningScope.Matches[i]) {
			return true
		}
	}
	return false
}

func isFrameworkFitToScanScope(framework reporthandling.Framework, scanScopeMatches reporthandling.ScanningScopeType) bool {
	// for backward compatibility - case: kubescape with scope(new one) and regolibrary without scope(old one)
	if framework.ScanningScope == nil {
		return true
	}
	if len(framework.ScanningScope.Matches) == 0 {
		return true
	}
	for i := range framework.ScanningScope.Matches {
		if isScanningScopeMatchToControlScope(scanScopeMatches, framework.ScanningScope.Matches[i]) {
			return true
		}
	}
	return false
}
