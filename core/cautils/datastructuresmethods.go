package cautils

import (
	"golang.org/x/mod/semver"

	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

func NewPolicies() *Policies {
	return &Policies{
		Frameworks: make([]string, 0),
		Controls:   make(map[string]reporthandling.Control),
	}
}

func (policies *Policies) Set(frameworks []reporthandling.Framework, excludedRules map[string]bool, scanningScope reporthandling.ScanningScopeType) {
	for i := range frameworks {
		if !isFrameworkFitToScanScope(frameworks[i], scanningScope) {
			continue
		}
		if frameworks[i].Name != "" && len(frameworks[i].Controls) > 0 {
			policies.Frameworks = append(policies.Frameworks, frameworks[i].Name)
		}
		for j := range frameworks[i].Controls {
			compatibleRules := []reporthandling.PolicyRule{}
			for r := range frameworks[i].Controls[j].Rules {
				if excludedRules != nil {
					ruleName := frameworks[i].Controls[j].Rules[r].Name
					if _, exclude := excludedRules[ruleName]; exclude {
						continue
					}
				}

				if ShouldSkipRule(frameworks[i].Controls[j], frameworks[i].Controls[j].Rules[r], scanningScope) {
					continue
				}
				// if isRuleKubescapeVersionCompatible(frameworks[i].Controls[j].Rules[r].Attributes, version) && isControlFitToScanScope(frameworks[i].Controls[j], scanningScope) {
				compatibleRules = append(compatibleRules, frameworks[i].Controls[j].Rules[r])
				// }
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

// ShouldSkipRule checks if the rule should be skipped
// It checks the following:
//  1. Rule is compatible with the current kubescape version
//  2. Rule fits the current scanning scope
func ShouldSkipRule(control reporthandling.Control, rule reporthandling.PolicyRule, scanningScope reporthandling.ScanningScopeType) bool {
	if !isRuleKubescapeVersionCompatible(rule.Attributes, versioncheck.BuildNumber) {
		return true
	}
	if !isControlFitToScanScope(control, scanningScope) {
		return true
	}
	return false
}

// Checks that kubescape version is in range of use for this rule
// In local build (BuildNumber = ""):
// returns true only if rule doesn't have the "until" attribute
func isRuleKubescapeVersionCompatible(attributes map[string]interface{}, version string) bool {
	if from, ok := attributes["useFromKubescapeVersion"]; ok && from != nil {
		switch sfrom := from.(type) {
		case string:
			if version != "" && semver.Compare(version, sfrom) == -1 {
				return false
			}
		default:
			// Handle case where useFromKubescapeVersion is not a string
			return false
		}
	}

	if until, ok := attributes["useUntilKubescapeVersion"]; ok && until != nil {
		switch suntil := until.(type) {
		case string:
			if version == "" || semver.Compare(version, suntil) >= 0 {
				return false
			}
		default:
			// Handle case where useUntilKubescapeVersion is not a string
			return false
		}
	}
	return true
}

func isScanningScopeMatchToControlScope(scanScope reporthandling.ScanningScopeType, controlScope reporthandling.ScanningScopeType) bool {

	switch controlScope {
	case reporthandling.ScopeFile:
		return reporthandling.ScopeFile == scanScope
	case reporthandling.ScopeCluster:
		return reporthandling.ScopeCluster == scanScope || reporthandling.ScopeCloud == scanScope || reporthandling.ScopeCloudAKS == scanScope || reporthandling.ScopeCloudEKS == scanScope || reporthandling.ScopeCloudGKE == scanScope
	case reporthandling.ScopeCloud:
		return reporthandling.ScopeCloud == scanScope || reporthandling.ScopeCloudAKS == scanScope || reporthandling.ScopeCloudEKS == scanScope || reporthandling.ScopeCloudGKE == scanScope
	case reporthandling.ScopeCloudAKS:
		return reporthandling.ScopeCloudAKS == scanScope
	case reporthandling.ScopeCloudEKS:
		return reporthandling.ScopeCloudEKS == scanScope
	case reporthandling.ScopeCloudGKE:
		return reporthandling.ScopeCloudGKE == scanScope
	default:
		return true
	}
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

func GetScanningScope(ContextMetadata reporthandlingv2.ContextMetadata) reporthandling.ScanningScopeType {
	if ContextMetadata.ClusterContextMetadata != nil {
		if ContextMetadata.ClusterContextMetadata.CloudMetadata != nil && ContextMetadata.ClusterContextMetadata.CloudMetadata.CloudProvider != "" {
			return reporthandling.ScanningScopeType(ContextMetadata.ClusterContextMetadata.CloudMetadata.CloudProvider)
		}
		return reporthandling.ScopeCluster
	}
	return reporthandling.ScopeFile
}
