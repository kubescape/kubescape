package cautils

import (
	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"golang.org/x/mod/semver"
)

func NewPolicies() *Policies {
	return &Policies{
		Frameworks: make([]string, 0),
		Controls:   make(map[string]reporthandling.Control),
	}
}

func (policies *Policies) Set(frameworks []reporthandling.Framework, excludedRules map[string]bool, scanningScope reporthandling.ScanningScopeType) {
	warned := make(map[string]struct{})
	for i := range frameworks {
		if !isFrameworkFitToScanScope(frameworks[i], scanningScope) {
			continue
		}
		if frameworks[i].Name != "" && len(frameworks[i].Controls) > 0 {
			policies.Frameworks = append(policies.Frameworks, frameworks[i].Name)
		}
		for j := range frameworks[i].Controls {
			// operate on a local copy so we never mutate the caller's backing array -
			// frameworks may be a cached slice reused across scans (see PolicyHandler's cachedFrameworks)
			control := frameworks[i].Controls[j]
			compatibleRules := []reporthandling.PolicyRule{}
			for r := range control.Rules {
				if excludedRules != nil {
					ruleName := control.Rules[r].Name
					if _, exclude := excludedRules[ruleName]; exclude {
						continue
					}
				}

				if shouldSkipRule(control, control.Rules[r], scanningScope, warned) {
					continue
				}
				// if isRuleKubescapeVersionCompatible(control.Rules[r].Attributes, version) && isControlFitToScanScope(control, scanningScope) {
				compatibleRules = append(compatibleRules, control.Rules[r])
				// }
			}
			if len(compatibleRules) > 0 {
				control.Rules = compatibleRules
				policies.Controls[control.ControlID] = control
			} else { // if the control type is manual review, add it to the list of controls
				actionRequiredStr := control.GetActionRequiredAttribute()
				if actionRequiredStr == "" {
					continue
				}
				if actionRequiredStr == string(apis.SubStatusManualReview) {
					policies.Controls[control.ControlID] = control
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
	return shouldSkipRule(control, rule, scanningScope, make(map[string]struct{}))
}

func shouldSkipRule(control reporthandling.Control, rule reporthandling.PolicyRule, scanningScope reporthandling.ScanningScopeType, warned map[string]struct{}) bool {
	if !isRuleKubescapeVersionCompatible(rule.Name, rule.Attributes, versioncheck.BuildNumber, warned) {
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
func isRuleKubescapeVersionCompatible(ruleName string, attributes map[string]any, version string, warned map[string]struct{}) bool {
	normalizedVersion := version
	if version != "" && !semver.IsValid(version) {
		normalizedVersion = "v" + version
	}

	if from, ok := attributes["useFromKubescapeVersion"]; ok && from != nil {
		switch sfrom := from.(type) {
		case string:
			if normalizedVersion != "" && semver.IsValid(normalizedVersion) && !semver.IsValid(sfrom) {
				key := ruleName + ":useFromKubescapeVersion:" + sfrom
				if _, seen := warned[key]; !seen {
					warned[key] = struct{}{}
					logger.L().Warning("invalid useFromKubescapeVersion in rule attributes, rule may run on unintended versions",
						helpers.String("useFromKubescapeVersion", sfrom),
						helpers.String("rule", ruleName))
				}
			}
			if normalizedVersion != "" && semver.IsValid(normalizedVersion) && semver.Compare(normalizedVersion, sfrom) == -1 {
				return false
			}
		default:
			logger.L().Warning("non-string useFromKubescapeVersion in rule attributes, skipping rule",
				helpers.String("rule", ruleName))
			return false
		}
	}

	if until, ok := attributes["useUntilKubescapeVersion"]; ok && until != nil {
		switch suntil := until.(type) {
		case string:
			if !semver.IsValid(suntil) {
				key := ruleName + ":useUntilKubescapeVersion:" + suntil
				if _, seen := warned[key]; !seen {
					warned[key] = struct{}{}
					logger.L().Warning("invalid useUntilKubescapeVersion in rule attributes, skipping rule",
						helpers.String("useUntilKubescapeVersion", suntil),
						helpers.String("rule", ruleName))
				}
				return false
			}
			if normalizedVersion == "" || semver.Compare(normalizedVersion, suntil) >= 0 {
				return false
			}
		default:
			logger.L().Warning("non-string useUntilKubescapeVersion in rule attributes, skipping rule",
				helpers.String("rule", ruleName))
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
