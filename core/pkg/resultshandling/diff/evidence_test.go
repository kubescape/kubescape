package diff

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func failedRule(name string, paths ...evidencePath) ruleEntry {
	return ruleEntry{Name: name, Status: "failed", Paths: paths}
}

func passedRule(name string, paths ...evidencePath) ruleEntry {
	return ruleEntry{Name: name, Status: "passed", Paths: paths}
}

func failedControlWithRules(id, name string, rules ...ruleEntry) controlEntry {
	control := makeControl(id, name, "failed")
	control.Rules = rules
	return control
}

func TestNormalizeEvidencePath(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: "", want: ""},
		{name: "whitespace", input: "   ", want: ""},
		{name: "root only", input: "$", want: ""},
		{name: "root with whitespace", input: "  $  ", want: ""},
		{name: "dollar dot notation", input: "$.spec.hostNetwork", want: "spec.hostNetwork"},
		{name: "dollar notation", input: "$spec.hostNetwork", want: "spec.hostNetwork"},
		{name: "leading dot notation", input: ".spec.hostNetwork", want: "spec.hostNetwork"},
		{name: "plain path", input: "spec.hostNetwork", want: "spec.hostNetwork"},
		{name: "surrounding whitespace", input: "  $.spec.containers[0].securityContext  ", want: "spec.containers[0].securityContext"},
		{name: "keeps inner spaces", input: `$.metadata.labels["team name"]`, want: `metadata.labels["team name"]`},
		{name: "keeps case", input: "$.Spec.HostPID", want: "Spec.HostPID"},
		{name: "keeps indices", input: "$.spec.containers[12].image", want: "spec.containers[12].image"},
		{name: "keeps wildcard", input: "$.spec.containers[*].image", want: "spec.containers[*].image"},
		{name: "keeps slash syntax", input: "/spec/template/spec/hostPID", want: "/spec/template/spec/hostPID"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, normalizeEvidencePath(test.input))
		})
	}
}

func TestFindingsForControl_ControlGranularity(t *testing.T) {
	controlKey := key{resourceID: "/v1/default/Pod/demo", controlID: "C-001"}
	control := failedControlWithRules(
		"C-001",
		"Control",
		failedRule("host-network", evidencePath{}),
		failedRule("host-pid", evidencePath{}),
	)

	findings := findingsForControl(controlKey, control, "High", GranularityControl)

	require.Len(t, findings, 1)
	assert.Equal(t, findingFingerprint{
		resourceID:   "/v1/default/Pod/demo",
		controlID:    "C-001",
		evidenceType: evidenceTypeControl,
	}, findings[0].fingerprint)
	assert.Equal(t, "Control", findings[0].controlName)
	assert.Equal(t, "High", findings[0].severity)
}

func TestFindingsForControl_ExtractsFailedAndReviewPaths(t *testing.T) {
	controlKey := key{resourceID: "/v1/default/Pod/demo", controlID: "C-002"}
	control := failedControlWithRules(
		"C-002",
		"Workload configuration",
		failedRule("container-security", evidencePath{
			ResourceID: "/v1/default/Pod/demo",
			ReviewPath: "$.spec.containers[0].securityContext.capabilities",
		}),
	)

	findings := findingsForControl(controlKey, control, "Critical", GranularityEvidence)

	require.Len(t, findings, 2)
	assert.Equal(t, evidenceTypeReviewPath, findings[0].fingerprint.evidenceType)
	assert.Equal(t, "spec.containers[0].securityContext.privileged", findings[0].fingerprint.path)
	assert.Equal(t, "container-security", findings[0].fingerprint.ruleName)
	assert.Equal(t, "/v1/default/Pod/demo", findings[0].fingerprint.evidenceResourceID)
	assert.Equal(t, evidenceTypeReviewPath, findings[1].fingerprint.evidenceType)
	assert.Equal(t, "spec.containers[0].securityContext.capabilities", findings[1].fingerprint.path)
}

func TestFindingsForControl_ExtractsAllPosturePathEvidence(t *testing.T) {
	controlKey := key{resourceID: "/v1/default/Pod/demo", controlID: "C-010"}
	control := failedControlWithRules(
		"C-010",
		"Workload configuration",
		failedRule("container-security", evidencePath{
			ResourceID: "/v1/default/Pod/demo",
			ReviewPath: "$.spec.containers[0].securityContext.capabilities",
			DeletePath: "$.spec.hostNetwork",
			FixPath:    fixPath{Path: "$.spec.securityContext.runAsNonRoot", Value: []byte("true")},
			FixCommand: "kubectl patch deployment demo",
		}),
	)

	findings := findingsForControl(controlKey, control, "Critical", GranularityEvidence)

	require.Len(t, findings, 5)
	assert.ElementsMatch(t, []findingFingerprint{
		{resourceID: "/v1/default/Pod/demo", controlID: "C-010", ruleName: "container-security", evidenceType: evidenceTypeReviewPath, path: "spec.containers[0].securityContext.privileged", evidenceResourceID: "/v1/default/Pod/demo"},
		{resourceID: "/v1/default/Pod/demo", controlID: "C-010", ruleName: "container-security", evidenceType: evidenceTypeReviewPath, path: "spec.containers[0].securityContext.capabilities", evidenceResourceID: "/v1/default/Pod/demo"},
		{resourceID: "/v1/default/Pod/demo", controlID: "C-010", ruleName: "container-security", evidenceType: evidenceTypeDeletePath, path: "spec.hostNetwork", evidenceResourceID: "/v1/default/Pod/demo"},
		{resourceID: "/v1/default/Pod/demo", controlID: "C-010", ruleName: "container-security", evidenceType: evidenceTypeFixPath, path: "spec.securityContext.runAsNonRoot", evidenceResourceID: "/v1/default/Pod/demo"},
		{resourceID: "/v1/default/Pod/demo", controlID: "C-010", ruleName: "container-security", evidenceType: evidenceTypeFixCommand, path: "kubectl patch deployment demo", evidenceResourceID: "/v1/default/Pod/demo"},
	}, []findingFingerprint{
		findings[0].fingerprint,
		findings[1].fingerprint,
		findings[2].fingerprint,
		findings[3].fingerprint,
		findings[4].fingerprint,
	})
}

func TestFindingsForControl_PathlessFailedRuleUsesRuleFingerprint(t *testing.T) {
	controlKey := key{resourceID: "apps/v1/default/Deployment/api", controlID: "C-003"}
	control := failedControlWithRules(
		"C-003",
		"Pathless rule control",
		failedRule("image-vulnerability"),
	)

	findings := findingsForControl(controlKey, control, "Medium", GranularityEvidence)

	require.Len(t, findings, 1)
	assert.Equal(t, findingFingerprint{
		resourceID:   "apps/v1/default/Deployment/api",
		controlID:    "C-003",
		ruleName:     "image-vulnerability",
		evidenceType: evidenceTypeRule,
	}, findings[0].fingerprint)
}

func TestFindingsForControl_EmptyPathsUseRuleFingerprint(t *testing.T) {
	controlKey := key{resourceID: "resource", controlID: "C-004"}
	control := failedControlWithRules(
		"C-004",
		"Control",
		failedRule("empty-paths",
			evidencePath{},
			evidencePath{ReviewPath: "$"},
		),
	)

	findings := findingsForControl(controlKey, control, "Low", GranularityEvidence)

	require.Len(t, findings, 1)
	assert.Equal(t, evidenceTypeRule, findings[0].fingerprint.evidenceType)
	assert.Equal(t, "empty-paths", findings[0].fingerprint.ruleName)
}

func TestFindingsForControl_IgnoresNonFailedRules(t *testing.T) {
	statuses := []string{"passed", "skipped", "excluded", "irrelevant", "error"}
	rules := make([]ruleEntry, 0, len(statuses))
	for _, status := range statuses {
		rules = append(rules, ruleEntry{
			Name:   "rule-" + status,
			Status: status,
			Paths:  []evidencePath{{ReviewPath: "$.spec." + status}},
		})
	}
	controlKey := key{resourceID: "resource", controlID: "C-005"}
	control := failedControlWithRules("C-005", "Control", rules...)

	findings := findingsForControl(controlKey, control, "High", GranularityEvidence)

	require.Len(t, findings, 1)
	assert.Equal(t, evidenceTypeControl, findings[0].fingerprint.evidenceType)
}

func TestFindingsForControl_MixedRuleStatuses(t *testing.T) {
	controlKey := key{resourceID: "resource", controlID: "C-006"}
	control := failedControlWithRules(
		"C-006",
		"Control",
		passedRule("passing", evidencePath{}),
		failedRule("failing", evidencePath{}),
		ruleEntry{Name: "skipped", Status: "skipped", Paths: []evidencePath{{}}},
	)

	findings := findingsForControl(controlKey, control, "High", GranularityEvidence)

	require.Len(t, findings, 1)
	assert.Equal(t, "failing", findings[0].fingerprint.ruleName)
	assert.Equal(t, "included", findings[0].fingerprint.path)
}

func TestFindingsForControl_DeduplicatesIdenticalEvidence(t *testing.T) {
	controlKey := key{resourceID: "resource", controlID: "C-007"}
	control := failedControlWithRules(
		"C-007",
		"Control",
		failedRule("duplicate",
			evidencePath{ResourceID: "resource"},
			evidencePath{ResourceID: "resource"},
			evidencePath{ResourceID: "resource"},
		),
	)

	findings := findingsForControl(controlKey, control, "High", GranularityEvidence)

	require.Len(t, findings, 1)
	assert.Equal(t, "spec.hostPID", findings[0].fingerprint.path)
}

func TestFindingsForControl_DoesNotMergeDistinctEvidence(t *testing.T) {
	controlKey := key{resourceID: "resource", controlID: "C-008"}
	control := failedControlWithRules(
		"C-008",
		"Control",
		failedRule("rule-a", evidencePath{ResourceID: "child-a"}),
		failedRule("rule-b", evidencePath{ResourceID: "child-a"}),
		failedRule("rule-a", evidencePath{ResourceID: "child-b"}),
		failedRule("rule-a", evidencePath{ResourceID: "child-a", ReviewPath: "$.spec.hostPID"}),
	)

	findings := findingsForControl(controlKey, control, "High", GranularityEvidence)

	require.Len(t, findings, 4)
	assert.ElementsMatch(t, []findingFingerprint{
		{resourceID: "resource", controlID: "C-008", ruleName: "rule-a", evidenceType: evidenceTypeReviewPath, path: "spec.hostPID", evidenceResourceID: "child-a"},
		{resourceID: "resource", controlID: "C-008", ruleName: "rule-a", evidenceType: evidenceTypeReviewPath, path: "spec.hostPID", evidenceResourceID: "child-b"},
		{resourceID: "resource", controlID: "C-008", ruleName: "rule-a", evidenceType: evidenceTypeReviewPath, path: "spec.hostPID", evidenceResourceID: "child-a"},
		{resourceID: "resource", controlID: "C-008", ruleName: "rule-b", evidenceType: evidenceTypeReviewPath, path: "spec.hostPID", evidenceResourceID: "child-a"},
	}, []findingFingerprint{
		findings[0].fingerprint,
		findings[1].fingerprint,
		findings[2].fingerprint,
		findings[3].fingerprint,
	})
}

func TestFindingChangeCopiesEvidenceFields(t *testing.T) {
	item := finding{
		fingerprint: findingFingerprint{
			resourceID:         "resource",
			controlID:          "C-009",
			ruleName:           "rule",
			evidenceType:       evidenceTypeReviewPath,
			path:               "spec.hostIPC",
			evidenceResourceID: "related-resource",
		},
		controlName: "Control name",
		severity:    "Critical",
	}

	change := item.change("failed", "failed", "comparison reason")

	assert.Equal(t, "resource", change.ResourceID)
	assert.Equal(t, "C-009", change.ControlID)
	assert.Equal(t, "Control name", change.ControlName)
	assert.Equal(t, "Critical", change.Severity)
	assert.Equal(t, "failed", change.BaseStatus)
	assert.Equal(t, "failed", change.HeadStatus)
	assert.Equal(t, "rule", change.RuleName)
	assert.Equal(t, evidenceTypeReviewPath, change.EvidenceType)
	assert.Equal(t, "spec.hostIPC", change.Path)
	assert.Equal(t, "related-resource", change.EvidenceResourceID)
	assert.Equal(t, "comparison reason", change.Reason)
}

func TestEvidenceDetailMismatch(t *testing.T) {
	aggregate := []finding{{fingerprint: findingFingerprint{evidenceType: evidenceTypeControl}}}
	detailed := []finding{{fingerprint: findingFingerprint{evidenceType: evidenceTypeRule}}}
	paths := []finding{{fingerprint: findingFingerprint{evidenceType: evidenceTypeReviewPath}}}

	assert.False(t, evidenceDetailMismatch(aggregate, aggregate))
	assert.False(t, evidenceDetailMismatch(detailed, detailed))
	assert.True(t, evidenceDetailMismatch(detailed, paths))
	assert.True(t, evidenceDetailMismatch(aggregate, detailed))
	assert.True(t, evidenceDetailMismatch(paths, aggregate))
}

func TestDeduplicateFindingsUsesFullFingerprint(t *testing.T) {
	base := finding{
		fingerprint: findingFingerprint{
			resourceID:         "resource",
			controlID:          "control",
			ruleName:           "rule",
			evidenceType:       evidenceTypeReviewPath,
			path:               "path",
			evidenceResourceID: "evidence-resource",
		},
	}
	duplicate := base
	differentControl := base
	differentControl.fingerprint.controlID = "other-control"
	differentPath := base
	differentPath.fingerprint.path = "other-path"

	result := deduplicateFindings([]finding{base, duplicate, differentControl, differentPath})

	assert.Len(t, result, 3)
}
