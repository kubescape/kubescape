package diff

import (
	"sort"
	"strings"

	"github.com/kubescape/opa-utils/reporthandling/apis"
)

const (
	evidenceTypeControl    = "control"
	evidenceTypeRule       = "rule"
	evidenceTypeFailedPath = "failedPath"
	evidenceTypeReviewPath = "reviewPath"
	evidenceTypeDeletePath = "deletePath"
	evidenceTypeFixPath    = "fixPath"
	evidenceTypeFixCommand = "fixCommand"
)

type findingFingerprint struct {
	resourceID         string
	controlID          string
	ruleName           string
	evidenceType       string
	path               string
	evidenceResourceID string
}

type finding struct {
	fingerprint findingFingerprint
	controlName string
	severity    string
}

func (item finding) change(baseStatus, headStatus, reason string) ControlChange {
	return ControlChange{
		ResourceID:         item.fingerprint.resourceID,
		ControlID:          item.fingerprint.controlID,
		ControlName:        item.controlName,
		Severity:           item.severity,
		BaseStatus:         baseStatus,
		HeadStatus:         headStatus,
		RuleName:           item.fingerprint.ruleName,
		EvidenceType:       item.fingerprint.evidenceType,
		Path:               item.fingerprint.path,
		EvidenceResourceID: item.fingerprint.evidenceResourceID,
		Reason:             reason,
	}
}

func findingsForControl(controlKey key, control controlEntry, severity string, granularity Granularity) []finding {
	if granularity == GranularityControl {
		return []finding{aggregateFinding(controlKey, control, severity)}
	}

	findings := make([]finding, 0)
	for _, rule := range control.Rules {
		if rule.Status != string(apis.StatusFailed) {
			continue
		}
		failedRuleFindings := findingsForRule(controlKey, control, rule, severity)
		findings = append(findings, failedRuleFindings...)
	}
	if len(findings) == 0 {
		return []finding{aggregateFinding(controlKey, control, severity)}
	}
	return deduplicateFindings(findings)
}

func aggregateFinding(controlKey key, control controlEntry, severity string) finding {
	return finding{
		fingerprint: findingFingerprint{
			resourceID:   controlKey.resourceID,
			controlID:    controlKey.controlID,
			evidenceType: evidenceTypeControl,
		},
		controlName: control.Name,
		severity:    severity,
	}
}

func findingsForRule(controlKey key, control controlEntry, rule ruleEntry, severity string) []finding {
	findings := make([]finding, 0, len(rule.Paths)*5)
	for _, path := range rule.Paths {
		failedPath := normalizeEvidencePath(path.FailedPath)
		if failedPath != "" {
			findings = append(findings, makeEvidenceFinding(controlKey, control, rule.Name, evidenceTypeFailedPath, failedPath, path.ResourceID, severity))
		}
		reviewPath := normalizeEvidencePath(path.ReviewPath)
		if reviewPath != "" {
			findings = append(findings, makeEvidenceFinding(controlKey, control, rule.Name, evidenceTypeReviewPath, reviewPath, path.ResourceID, severity))
		}
		deletePath := normalizeEvidencePath(path.DeletePath)
		if deletePath != "" {
			findings = append(findings, makeEvidenceFinding(controlKey, control, rule.Name, evidenceTypeDeletePath, deletePath, path.ResourceID, severity))
		}
		fixPath := normalizeEvidencePath(path.FixPath.Path)
		if fixPath != "" {
			findings = append(findings, makeEvidenceFinding(controlKey, control, rule.Name, evidenceTypeFixPath, fixPath, path.ResourceID, severity))
		}
		fixCommand := normalizeEvidenceCommand(path.FixCommand)
		if fixCommand != "" {
			findings = append(findings, makeEvidenceFinding(controlKey, control, rule.Name, evidenceTypeFixCommand, fixCommand, path.ResourceID, severity))
		}
	}
	if len(findings) == 0 {
		findings = append(findings, makeEvidenceFinding(controlKey, control, rule.Name, evidenceTypeRule, "", "", severity))
	}
	return findings
}

func makeEvidenceFinding(controlKey key, control controlEntry, ruleName, evidenceType, path, evidenceResourceID, severity string) finding {
	return finding{
		fingerprint: findingFingerprint{
			resourceID:         strings.TrimSpace(controlKey.resourceID),
			controlID:          strings.TrimSpace(controlKey.controlID),
			ruleName:           strings.TrimSpace(ruleName),
			evidenceType:       evidenceType,
			path:               path,
			evidenceResourceID: strings.TrimSpace(evidenceResourceID),
		},
		controlName: control.Name,
		severity:    severity,
	}
}

// normalizeEvidencePath only removes equivalent JSONPath root notation and
// surrounding whitespace. It deliberately avoids case conversion, index
// rewriting, or wildcard expansion because those can merge distinct evidence.
func normalizeEvidencePath(value string) string {
	value = strings.TrimSpace(value)
	if value == "$" {
		return ""
	}
	value = strings.TrimPrefix(value, "$")
	value = strings.TrimPrefix(value, ".")
	return strings.TrimSpace(value)
}

func normalizeEvidenceCommand(value string) string {
	return strings.TrimSpace(value)
}

func deduplicateFindings(findings []finding) []finding {
	byFingerprint := indexFindings(findings)
	result := make([]finding, 0, len(byFingerprint))
	for _, item := range byFingerprint {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := result[i].fingerprint, result[j].fingerprint
		if left.ruleName != right.ruleName {
			return left.ruleName < right.ruleName
		}
		if left.evidenceType != right.evidenceType {
			return left.evidenceType < right.evidenceType
		}
		if left.path != right.path {
			return left.path < right.path
		}
		return left.evidenceResourceID < right.evidenceResourceID
	})
	return result
}

func indexFindings(findings []finding) map[findingFingerprint]finding {
	indexed := make(map[findingFingerprint]finding, len(findings))
	for _, item := range findings {
		indexed[item.fingerprint] = item
	}
	return indexed
}

func evidenceDetailMismatch(base, head []finding) bool {
	return detailLevels(base) != detailLevels(head)
}

func detailLevels(findings []finding) uint8 {
	var levels uint8
	for _, item := range findings {
		switch item.fingerprint.evidenceType {
		case evidenceTypeControl:
			levels |= 1
		case evidenceTypeRule:
			levels |= 2
		default:
			levels |= 4
		}
	}
	return levels
}
