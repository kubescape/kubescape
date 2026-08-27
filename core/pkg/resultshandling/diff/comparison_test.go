package diff

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testResource = "apps/v1/default/Deployment/api"
	testControl  = "C-1000"
	testRule     = "require-security-context"
)

func evidenceReport(resourceID string, control controlEntry) scanReport {
	return scanReport{
		Results: []resultEntry{makeResult(resourceID, control)},
		SummaryDetails: summaryDetails{Controls: map[string]controlSummary{
			control.ControlID: {Severity: "High", ScoreFactor: 7},
		}},
	}
}

func reportWithPath(path string) scanReport {
	return evidenceReport(testResource, failedControlWithRules(
		testControl,
		"Require a security context",
		failedRule(testRule, evidencePath{ResourceID: testResource, ReviewPath: path}),
	))
}

func computeReports(t *testing.T, base, head scanReport) *ChangeSet {
	t.Helper()
	result, err := Compute(writeTempReport(t, base), writeTempReport(t, head))
	require.NoError(t, err)
	return result
}

func computeReportsWithOptions(t *testing.T, base, head scanReport, options Options) *ChangeSet {
	t.Helper()
	result, err := ComputeWithOptions(writeTempReport(t, base), writeTempReport(t, head), options)
	require.NoError(t, err)
	return result
}

func TestComputeEvidence_DetectsPathAddedInsideFailingControl(t *testing.T) {
	base := reportWithPath("$.spec.template.spec.containers[0].securityContext.runAsNonRoot")
	head := reportWithPath("$.spec.template.spec.containers[0].securityContext.runAsNonRoot")
	head.Results[0].AssociatedControls[0].Rules[0].Paths = append(
		head.Results[0].AssociatedControls[0].Rules[0].Paths,
		evidencePath{
			ResourceID: testResource,
			ReviewPath: "spec.template.spec.containers[0].securityContext.privileged",
		},
	)

	changes := computeReports(t, base, head)

	require.Len(t, changes.New, 1)
	assert.Equal(t, testControl, changes.New[0].ControlID)
	assert.Equal(t, testRule, changes.New[0].RuleName)
	assert.Equal(t, evidenceTypeReviewPath, changes.New[0].EvidenceType)
	assert.Equal(t, "spec.template.spec.containers[0].securityContext.privileged", changes.New[0].Path)
	assert.Equal(t, "failed", changes.New[0].BaseStatus, "the aggregate control was already failed")
	assert.Equal(t, "failed", changes.New[0].HeadStatus)
	require.Len(t, changes.Unchanged, 1)
	assert.Equal(t, "spec.template.spec.containers[0].securityContext.runAsNonRoot", changes.Unchanged[0].Path)
	assert.Empty(t, changes.Resolved)
	assert.Empty(t, changes.Incomparable)
}

func TestComputeEvidence_DetectsNewFailedRuleInsideFailingControl(t *testing.T) {
	base := reportWithPath("$.spec.hostPID")
	head := reportWithPath("$.spec.hostPID")
	head.Results[0].AssociatedControls[0].Rules = append(
		head.Results[0].AssociatedControls[0].Rules,
		failedRule("disallow-host-ipc", evidencePath{ReviewPath: "spec.hostIPC"}),
	)

	changes := computeReports(t, base, head)

	require.Len(t, changes.New, 1)
	assert.Equal(t, "disallow-host-ipc", changes.New[0].RuleName)
	assert.Equal(t, "spec.hostIPC", changes.New[0].Path)
	require.Len(t, changes.Unchanged, 1)
	assert.Empty(t, changes.Resolved)
}

func TestComputeEvidence_DetectsNewPosturePathEvidenceInsideFailingControl(t *testing.T) {
	tests := []struct {
		name         string
		existingPath evidencePath
		newPath      evidencePath
		evidenceType string
		wantPath     string
	}{
		{
			name:         "fix path",
			existingPath: evidencePath{FixPath: fixPath{Path: "$.spec.template.spec.containers[0].securityContext.runAsNonRoot", Value: []byte("true")}},
			newPath:      evidencePath{FixPath: fixPath{Path: "$.spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation", Value: []byte("false")}},
			evidenceType: evidenceTypeFixPath,
			wantPath:     "spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation",
		},
		{
			name:         "delete path",
			existingPath: evidencePath{DeletePath: "$.spec.hostPID"},
			newPath:      evidencePath{DeletePath: "$.spec.hostIPC"},
			evidenceType: evidenceTypeDeletePath,
			wantPath:     "spec.hostIPC",
		},
		{
			name:         "fix command",
			existingPath: evidencePath{FixCommand: "kubectl patch deploy api --type merge"},
			newPath:      evidencePath{FixCommand: "kubectl label ns default owner=platform"},
			evidenceType: evidenceTypeFixCommand,
			wantPath:     "kubectl label ns default owner=platform",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			base := evidenceReport(testResource, failedControlWithRules(testControl, "Control", failedRule(testRule, test.existingPath)))
			head := evidenceReport(testResource, failedControlWithRules(testControl, "Control", failedRule(testRule, test.existingPath, test.newPath)))

			changes := computeReports(t, base, head)

			require.Len(t, changes.New, 1)
			assert.Equal(t, test.evidenceType, changes.New[0].EvidenceType)
			assert.Equal(t, test.wantPath, changes.New[0].Path)
			assert.Empty(t, changes.Resolved)
			require.Len(t, changes.Unchanged, 1)
		})
	}
}

func TestComputeEvidence_DetectsPathResolvedInsideFailingControl(t *testing.T) {
	base := reportWithPath("$.spec.hostPID")
	base.Results[0].AssociatedControls[0].Rules[0].Paths = append(
		base.Results[0].AssociatedControls[0].Rules[0].Paths,
		evidencePath{ReviewPath: "$.spec.hostIPC"},
	)
	head := reportWithPath("$.spec.hostPID")

	changes := computeReports(t, base, head)

	require.Len(t, changes.Resolved, 1)
	assert.Equal(t, "spec.hostIPC", changes.Resolved[0].Path)
	assert.Equal(t, "failed", changes.Resolved[0].BaseStatus)
	assert.Equal(t, "failed", changes.Resolved[0].HeadStatus, "one evidence item resolved while the control remained failed")
	require.Len(t, changes.Unchanged, 1)
	assert.Empty(t, changes.New)
}

func TestComputeEvidence_EquivalentRootNotationIsUnchanged(t *testing.T) {
	base := reportWithPath("$.spec.hostPID")
	head := reportWithPath(".spec.hostPID")

	changes := computeReports(t, base, head)

	assert.Empty(t, changes.New)
	assert.Empty(t, changes.Resolved)
	require.Len(t, changes.Unchanged, 1)
	assert.Equal(t, "spec.hostPID", changes.Unchanged[0].Path)
}

func TestComputeEvidence_ReorderedRulesAndPathsAreUnchanged(t *testing.T) {
	baseControl := failedControlWithRules(
		testControl,
		"Control",
		failedRule("rule-a",
			evidencePath{ReviewPath: "$.spec.a"},
			evidencePath{ReviewPath: "$.spec.b"},
		),
		failedRule("rule-b",
			evidencePath{ReviewPath: "$.spec.c"},
		),
	)
	headControl := failedControlWithRules(
		testControl,
		"Control",
		failedRule("rule-b",
			evidencePath{ReviewPath: ".spec.c"},
		),
		failedRule("rule-a",
			evidencePath{ReviewPath: ".spec.a"},
			evidencePath{ReviewPath: ".spec.b"},
		),
	)

	changes := computeReports(t, evidenceReport(testResource, baseControl), evidenceReport(testResource, headControl))

	assert.Empty(t, changes.New)
	assert.Empty(t, changes.Resolved)
	require.Len(t, changes.Unchanged, 3)
	assert.Equal(t, []string{"spec.a", "spec.b", "spec.c"}, []string{
		changes.Unchanged[0].Path,
		changes.Unchanged[1].Path,
		changes.Unchanged[2].Path,
	})
}

func TestComputeEvidence_DuplicatePathsDoNotInflateCounts(t *testing.T) {
	base := reportWithPath("$.spec.hostPID")
	head := reportWithPath("$.spec.hostPID")
	head.Results[0].AssociatedControls[0].Rules[0].Paths = append(
		head.Results[0].AssociatedControls[0].Rules[0].Paths,
		evidencePath{ResourceID: testResource},
		evidencePath{ResourceID: testResource},
	)

	changes := computeReports(t, base, head)

	assert.Empty(t, changes.New)
	assert.Empty(t, changes.Resolved)
	assert.Len(t, changes.Unchanged, 1)
}

func TestComputeEvidence_PathlessFailedRulesCompareByRuleName(t *testing.T) {
	base := evidenceReport(testResource, failedControlWithRules(
		testControl,
		"Control",
		failedRule("existing-rule"),
	))
	head := evidenceReport(testResource, failedControlWithRules(
		testControl,
		"Control",
		failedRule("existing-rule"),
		failedRule("new-rule"),
	))

	changes := computeReports(t, base, head)

	require.Len(t, changes.New, 1)
	assert.Equal(t, "new-rule", changes.New[0].RuleName)
	assert.Equal(t, evidenceTypeRule, changes.New[0].EvidenceType)
	assert.Empty(t, changes.New[0].Path)
	require.Len(t, changes.Unchanged, 1)
	assert.Equal(t, "existing-rule", changes.Unchanged[0].RuleName)
}

func TestComputeEvidence_ReviewAndDeletePathsAreDifferentEvidence(t *testing.T) {
	base := evidenceReport(testResource, failedControlWithRules(
		testControl,
		"Control",
		failedRule(testRule, evidencePath{ReviewPath: "$.spec.hostPID"}),
	))
	head := evidenceReport(testResource, failedControlWithRules(
		testControl,
		"Control",
		failedRule(testRule, evidencePath{DeletePath: "$.spec.hostPID"}),
	))

	changes := computeReports(t, base, head)

	require.Len(t, changes.New, 1)
	assert.Equal(t, evidenceTypeDeletePath, changes.New[0].EvidenceType)
	require.Len(t, changes.Resolved, 1)
	assert.Equal(t, evidenceTypeReviewPath, changes.Resolved[0].EvidenceType)
	assert.Empty(t, changes.Unchanged)
}

func TestComputeEvidence_EvidenceResourceIDParticipatesInIdentity(t *testing.T) {
	base := reportWithPath("$.spec.hostPID")
	base.Results[0].AssociatedControls[0].Rules[0].Paths[0].ResourceID = "child-a"
	head := reportWithPath("$.spec.hostPID")
	head.Results[0].AssociatedControls[0].Rules[0].Paths[0].ResourceID = "child-b"

	changes := computeReports(t, base, head)

	require.Len(t, changes.New, 1)
	assert.Equal(t, "child-b", changes.New[0].EvidenceResourceID)
	require.Len(t, changes.Resolved, 1)
	assert.Equal(t, "child-a", changes.Resolved[0].EvidenceResourceID)
}

func TestComputeEvidence_DetailedAndLegacyFailuresAreIncomparable(t *testing.T) {
	legacy := evidenceReport(testResource, makeControl(testControl, "Control", "failed"))
	detailed := reportWithPath("$.spec.hostPID")

	for _, test := range []struct {
		name string
		base scanReport
		head scanReport
	}{
		{name: "legacy base", base: legacy, head: detailed},
		{name: "legacy head", base: detailed, head: legacy},
	} {
		t.Run(test.name, func(t *testing.T) {
			changes := computeReports(t, test.base, test.head)

			assert.Empty(t, changes.New)
			assert.Empty(t, changes.Resolved)
			assert.Empty(t, changes.Unchanged)
			require.Len(t, changes.Incomparable, 2)
			for _, change := range changes.Incomparable {
				assert.Contains(t, change.Reason, "different failed evidence detail")
			}
		})
	}
}

func TestComputeEvidence_RuleAndPathLevelFailuresAreIncomparable(t *testing.T) {
	base := evidenceReport(testResource, failedControlWithRules(testControl, "Control", failedRule(testRule)))
	head := reportWithPath("$.spec.hostPID")

	changes := computeReports(t, base, head)

	assert.Empty(t, changes.New)
	assert.Empty(t, changes.Resolved)
	assert.Empty(t, changes.Unchanged)
	require.Len(t, changes.Incomparable, 2)
	for _, change := range changes.Incomparable {
		assert.Contains(t, change.Reason, "different failed evidence detail")
	}
}

func TestComputeEvidence_TwoLegacyFailuresRemainCompatible(t *testing.T) {
	base := evidenceReport(testResource, makeControl(testControl, "Control", "failed"))
	head := evidenceReport(testResource, makeControl(testControl, "Control", "failed"))

	changes := computeReports(t, base, head)

	assert.Empty(t, changes.New)
	assert.Empty(t, changes.Resolved)
	require.Len(t, changes.Unchanged, 1)
	assert.Equal(t, evidenceTypeControl, changes.Unchanged[0].EvidenceType)
}

func TestComputeControlGranularity_PreservesAggregateBehavior(t *testing.T) {
	base := reportWithPath("$.spec.hostPID")
	head := reportWithPath("$.spec.hostPID")
	head.Results[0].AssociatedControls[0].Rules[0].Paths = append(
		head.Results[0].AssociatedControls[0].Rules[0].Paths,
		evidencePath{},
	)

	changes := computeReportsWithOptions(t, base, head, Options{Granularity: GranularityControl})

	assert.Empty(t, changes.New)
	assert.Empty(t, changes.Resolved)
	require.Len(t, changes.Unchanged, 1)
	assert.Equal(t, evidenceTypeControl, changes.Unchanged[0].EvidenceType)
	assert.Empty(t, changes.Unchanged[0].RuleName)
	assert.Empty(t, changes.Unchanged[0].Path)
}

func TestComputeEvidence_StatusTransitions(t *testing.T) {
	tests := []struct {
		name             string
		baseStatus       string
		baseSubStatus    string
		headStatus       string
		headSubStatus    string
		wantNew          int
		wantResolved     int
		wantIncomparable int
	}{
		{name: "passed to failed is new", baseStatus: "passed", headStatus: "failed", wantNew: 1},
		{name: "failed to passed is resolved", baseStatus: "failed", headStatus: "passed", wantResolved: 1},
		{name: "skipped to failed is incomparable", baseStatus: "skipped", headStatus: "failed", wantIncomparable: 1},
		{name: "error to failed is incomparable", baseStatus: "error", headStatus: "failed", wantIncomparable: 1},
		{name: "unknown to failed is incomparable", baseStatus: "unknown", headStatus: "failed", wantIncomparable: 1},
		{name: "failed to skipped is incomparable", baseStatus: "failed", headStatus: "skipped", wantIncomparable: 1},
		{name: "failed to error is incomparable", baseStatus: "failed", headStatus: "error", wantIncomparable: 1},
		{name: "failed to passed not evaluated is incomparable", baseStatus: "failed", headStatus: "passed", headSubStatus: "notEvaluated", wantIncomparable: 1},
		{name: "not evaluated passed to failed is incomparable", baseStatus: "passed", baseSubStatus: "notEvaluated", headStatus: "failed", wantIncomparable: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			baseControl := makeControl(testControl, "Control", test.baseStatus)
			baseControl.Status.SubStatus = test.baseSubStatus
			headControl := makeControl(testControl, "Control", test.headStatus)
			headControl.Status.SubStatus = test.headSubStatus
			if test.baseStatus == "failed" {
				baseControl = failedControlWithRules(testControl, "Control", failedRule(testRule, evidencePath{}))
			}
			if test.headStatus == "failed" {
				headControl = failedControlWithRules(testControl, "Control", failedRule(testRule, evidencePath{}))
			}
			changes := computeReports(t, evidenceReport(testResource, baseControl), evidenceReport(testResource, headControl))

			assert.Len(t, changes.New, test.wantNew)
			assert.Len(t, changes.Resolved, test.wantResolved)
			assert.Len(t, changes.Incomparable, test.wantIncomparable)
			if test.wantIncomparable > 0 {
				assert.NotEmpty(t, changes.Incomparable[0].Reason)
			}
		})
	}
}

func TestComputeEvidence_AbsentFailureResolutionSafety(t *testing.T) {
	base := reportWithPath("$.spec.hostPID")

	tests := []struct {
		name             string
		mutateHead       func(*scanReport)
		wantResolved     int
		wantIncomparable int
		wantReason       string
	}{
		{
			name:         "legacy empty head resolves removed resource",
			mutateHead:   func(*scanReport) {},
			wantResolved: 1,
		},
		{
			name: "declared scope missing control is incomparable",
			mutateHead: func(head *scanReport) {
				head.SummaryDetails.Controls["C-OTHER"] = controlSummary{Severity: "Low"}
			},
			wantIncomparable: 1,
			wantReason:       "declared control scope",
		},
		{
			name: "not evaluated control is incomparable",
			mutateHead: func(head *scanReport) {
				head.SummaryDetails.Controls[testControl] = controlSummary{Severity: "High"}
				head.ScanCoverage.NotEvaluatedControls = []notEvaluatedControl{{ControlID: testControl, Reason: "timeout"}}
			},
			wantIncomparable: 1,
			wantReason:       "not evaluated",
		},
		{
			name: "degraded coverage is incomparable",
			mutateHead: func(head *scanReport) {
				head.SummaryDetails.Controls[testControl] = controlSummary{Severity: "High"}
				head.ScanCoverage.Degraded = true
			},
			wantIncomparable: 1,
			wantReason:       "degraded scan coverage",
		},
		{
			name: "failed GVR pull is incomparable even without degraded bit",
			mutateHead: func(head *scanReport) {
				head.SummaryDetails.Controls[testControl] = controlSummary{Severity: "High"}
				head.ScanCoverage.FailedGVRPulls = []json.RawMessage{json.RawMessage(`{"gvr":"apps/v1/deployments"}`)}
			},
			wantIncomparable: 1,
			wantReason:       "degraded scan coverage",
		},
		{
			name: "partial GVR pull is incomparable",
			mutateHead: func(head *scanReport) {
				head.SummaryDetails.Controls[testControl] = controlSummary{Severity: "High"}
				head.ScanCoverage.PartialGVRPulls = []json.RawMessage{json.RawMessage(`{"gvr":"apps/v1/deployments"}`)}
			},
			wantIncomparable: 1,
			wantReason:       "degraded scan coverage",
		},
		{
			name: "policy degradation is incomparable",
			mutateHead: func(head *scanReport) {
				head.SummaryDetails.Controls[testControl] = controlSummary{Severity: "High"}
				head.ScanCoverage.PolicyDegradations = []json.RawMessage{json.RawMessage(`{"component":"exceptions"}`)}
			},
			wantIncomparable: 1,
			wantReason:       "degraded scan coverage",
		},
		{
			name: "complete declared scope resolves removed resource",
			mutateHead: func(head *scanReport) {
				head.SummaryDetails.Controls[testControl] = controlSummary{Severity: "High"}
			},
			wantResolved: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			head := makeReport()
			test.mutateHead(&head)

			changes := computeReports(t, base, head)

			assert.Len(t, changes.Resolved, test.wantResolved)
			assert.Len(t, changes.Incomparable, test.wantIncomparable)
			if test.wantReason != "" {
				require.NotEmpty(t, changes.Incomparable)
				assert.Contains(t, changes.Incomparable[0].Reason, test.wantReason)
			}
		})
	}
}

func TestComputeEvidence_BothFailedNewEvidenceHonorsBaseCoverageSafety(t *testing.T) {
	base := reportWithPath("$.spec.hostPID")
	base.ScanCoverage.Degraded = true
	head := reportWithPath("$.spec.hostPID")
	head.Results[0].AssociatedControls[0].Rules[0].Paths = append(
		head.Results[0].AssociatedControls[0].Rules[0].Paths,
		evidencePath{ReviewPath: "$.spec.hostIPC"},
	)

	changes := computeReports(t, base, head)

	assert.Empty(t, changes.New)
	assert.Empty(t, changes.Resolved)
	require.Len(t, changes.Unchanged, 1)
	require.Len(t, changes.Incomparable, 1)
	assert.Contains(t, changes.Incomparable[0].Reason, "degraded scan coverage")
}

func TestComputeEvidence_BothFailedResolvedEvidenceHonorsHeadCoverageSafety(t *testing.T) {
	base := reportWithPath("$.spec.hostPID")
	base.Results[0].AssociatedControls[0].Rules[0].Paths = append(
		base.Results[0].AssociatedControls[0].Rules[0].Paths,
		evidencePath{ReviewPath: "$.spec.hostIPC"},
	)
	head := reportWithPath("$.spec.hostPID")
	head.ScanCoverage.NotEvaluatedControls = []notEvaluatedControl{{ControlID: testControl, Reason: "timeout"}}

	changes := computeReports(t, base, head)

	assert.Empty(t, changes.New)
	assert.Empty(t, changes.Resolved)
	require.Len(t, changes.Unchanged, 1)
	require.Len(t, changes.Incomparable, 1)
	assert.Contains(t, changes.Incomparable[0].Reason, "not evaluated")
}

func TestComputeEvidence_BothFailedResolvedEvidenceHonorsRuleSubStatus(t *testing.T) {
	base := reportWithPath("$.spec.hostPID")
	base.Results[0].AssociatedControls[0].Rules[0].Paths = append(
		base.Results[0].AssociatedControls[0].Rules[0].Paths,
		evidencePath{ReviewPath: "$.spec.hostIPC"},
	)
	head := reportWithPath("$.spec.hostPID")
	head.Results[0].AssociatedControls[0].Rules[0].SubStatus = "notEvaluated"

	changes := computeReports(t, base, head)

	assert.Empty(t, changes.New)
	assert.Empty(t, changes.Resolved)
	require.Len(t, changes.Unchanged, 1)
	require.Len(t, changes.Incomparable, 1)
	assert.Contains(t, changes.Incomparable[0].Reason, "was not evaluated")
}

func TestComputeEvidence_NewFailureScopeSafety(t *testing.T) {
	head := reportWithPath("$.spec.hostPID")

	tests := []struct {
		name             string
		base             scanReport
		wantNew          int
		wantIncomparable int
	}{
		{
			name:    "legacy empty base accepts new resource",
			base:    makeReport(),
			wantNew: 1,
		},
		{
			name: "declared scope missing control is incomparable",
			base: scanReport{SummaryDetails: summaryDetails{Controls: map[string]controlSummary{
				"C-OTHER": {Severity: "Low"},
			}}},
			wantIncomparable: 1,
		},
		{
			name: "declared scope includes control accepts new resource",
			base: scanReport{SummaryDetails: summaryDetails{Controls: map[string]controlSummary{
				testControl: {Severity: "High"},
			}}},
			wantNew: 1,
		},
		{
			name: "base not evaluated control is incomparable",
			base: scanReport{
				SummaryDetails: summaryDetails{Controls: map[string]controlSummary{
					testControl: {Severity: "High"},
				}},
				ScanCoverage: scanCoverage{
					NotEvaluatedControls: []notEvaluatedControl{{ControlID: testControl, Reason: "timeout"}},
				},
			},
			wantIncomparable: 1,
		},
		{
			name: "degraded base coverage is incomparable",
			base: scanReport{
				SummaryDetails: summaryDetails{Controls: map[string]controlSummary{
					testControl: {Severity: "High"},
				}},
				ScanCoverage: scanCoverage{Degraded: true},
			},
			wantIncomparable: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changes := computeReports(t, test.base, head)

			assert.Len(t, changes.New, test.wantNew)
			assert.Len(t, changes.Incomparable, test.wantIncomparable)
		})
	}
}

func TestComputeEvidence_IncompatibleScanScopes(t *testing.T) {
	tests := []struct {
		name       string
		mutateBase func(*scanReport)
		mutateHead func(*scanReport)
		wantReason string
	}{
		{
			name:       "target type",
			mutateBase: func(report *scanReport) { report.Metadata.ScanMetadata.TargetType = "cluster" },
			mutateHead: func(report *scanReport) { report.Metadata.ScanMetadata.TargetType = "repo" },
			wantReason: "scan target types differ",
		},
		{
			name: "scanning target enum",
			mutateBase: func(report *scanReport) {
				value := uint16(1)
				report.Metadata.ScanMetadata.ScanningTarget = &value
			},
			mutateHead: func(report *scanReport) {
				value := uint16(2)
				report.Metadata.ScanMetadata.ScanningTarget = &value
			},
			wantReason: "scanning targets differ",
		},
		{
			name:       "included namespaces",
			mutateBase: func(report *scanReport) { report.Metadata.ScanMetadata.IncludeNamespaces = []string{"default"} },
			mutateHead: func(report *scanReport) { report.Metadata.ScanMetadata.IncludeNamespaces = []string{"production"} },
			wantReason: "included namespaces differ",
		},
		{
			name:       "excluded namespaces",
			mutateBase: func(report *scanReport) { report.Metadata.ScanMetadata.ExcludedNamespaces = []string{"kube-system"} },
			mutateHead: func(report *scanReport) { report.Metadata.ScanMetadata.ExcludedNamespaces = []string{"monitoring"} },
			wantReason: "excluded namespaces differ",
		},
		{
			name:       "target names",
			mutateBase: func(report *scanReport) { report.Metadata.ScanMetadata.TargetNames = []string{"api"} },
			mutateHead: func(report *scanReport) { report.Metadata.ScanMetadata.TargetNames = []string{"worker"} },
			wantReason: "target names differ",
		},
		{
			name: "cluster context",
			mutateBase: func(report *scanReport) {
				report.Metadata.TargetMetadata.Cluster = &clusterContext{ContextName: "development"}
			},
			mutateHead: func(report *scanReport) {
				report.Metadata.TargetMetadata.Cluster = &clusterContext{ContextName: "production"}
			},
			wantReason: "cluster contexts differ",
		},
		{
			name: "repository owner",
			mutateBase: func(report *scanReport) {
				report.Metadata.TargetMetadata.Repo = &repoContext{Provider: "github", Owner: "team-a", Repo: "service"}
			},
			mutateHead: func(report *scanReport) {
				report.Metadata.TargetMetadata.Repo = &repoContext{Provider: "github", Owner: "team-b", Repo: "service"}
			},
			wantReason: "repository identities differ",
		},
		{
			name: "repository remote URL",
			mutateBase: func(report *scanReport) {
				report.Metadata.TargetMetadata.Repo = &repoContext{RemoteURL: "https://github.com/team/service-a.git"}
			},
			mutateHead: func(report *scanReport) {
				report.Metadata.TargetMetadata.Repo = &repoContext{RemoteURL: "https://github.com/team/service-b.git"}
			},
			wantReason: "repository identities differ",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			base := reportWithPath("$.spec.hostPID")
			head := reportWithPath("$.spec.hostIPC")
			test.mutateBase(&base)
			test.mutateHead(&head)

			changes := computeReports(t, base, head)

			assert.Empty(t, changes.New)
			assert.Empty(t, changes.Resolved)
			assert.Empty(t, changes.Unchanged)
			require.Len(t, changes.Warnings, 1)
			assert.Contains(t, changes.Warnings[0], test.wantReason)
			require.Len(t, changes.Incomparable, 2)
			for _, change := range changes.Incomparable {
				assert.Contains(t, change.Reason, test.wantReason)
			}
		})
	}
}

func TestComputeEvidence_CompatibleScopeMetadata(t *testing.T) {
	base := reportWithPath("$.spec.hostPID")
	head := reportWithPath("$.spec.hostPID")
	base.Metadata.ScanMetadata.TargetType = "repo"
	head.Metadata.ScanMetadata.TargetType = "repo"
	base.Metadata.ScanMetadata.IncludeNamespaces = []string{"production", "default", "default"}
	head.Metadata.ScanMetadata.IncludeNamespaces = []string{"default", "production"}
	base.Metadata.ScanMetadata.ExcludedNamespaces = []string{"kube-system", ""}
	head.Metadata.ScanMetadata.ExcludedNamespaces = []string{"kube-system"}
	base.Metadata.ScanMetadata.TargetNames = []string{"worker", "api"}
	head.Metadata.ScanMetadata.TargetNames = []string{"api", "worker"}
	base.Metadata.TargetMetadata.Repo = &repoContext{Provider: "GitHub", Owner: "Team", Repo: "Service", Branch: "main"}
	head.Metadata.TargetMetadata.Repo = &repoContext{Provider: "github", Owner: "team", Repo: "service", Branch: "feature"}

	changes := computeReports(t, base, head)

	assert.Empty(t, changes.Warnings)
	assert.Empty(t, changes.Incomparable)
	assert.Len(t, changes.Unchanged, 1)
}

func TestComputeEvidence_MissingMetadataDoesNotBreakLegacyComparison(t *testing.T) {
	base := reportWithPath("$.spec.hostPID")
	head := reportWithPath("$.spec.hostPID")
	head.Metadata.ScanMetadata.TargetType = "cluster"
	head.Metadata.TargetMetadata.Cluster = &clusterContext{ContextName: "production"}

	changes := computeReports(t, base, head)

	assert.Empty(t, changes.Warnings)
	assert.Empty(t, changes.Incomparable)
	assert.Len(t, changes.Unchanged, 1)
}

func TestComputeEvidence_SeverityComesFromOwningSide(t *testing.T) {
	base := reportWithPath("$.spec.old")
	head := reportWithPath("$.spec.new")
	base.SummaryDetails.Controls[testControl] = controlSummary{Severity: "Medium"}
	head.SummaryDetails.Controls[testControl] = controlSummary{Severity: "Critical"}

	changes := computeReports(t, base, head)

	require.Len(t, changes.New, 1)
	assert.Equal(t, "Critical", changes.New[0].Severity)
	require.Len(t, changes.Resolved, 1)
	assert.Equal(t, "Medium", changes.Resolved[0].Severity)
}

func TestComputeEvidence_DeterministicEvidenceOrder(t *testing.T) {
	base := evidenceReport(testResource, failedControlWithRules(
		testControl,
		"Control",
		failedRule("z-rule", evidencePath{ReviewPath: "$.z"}),
		failedRule("a-rule", evidencePath{ReviewPath: "$.a"}),
	))
	head := evidenceReport(testResource, failedControlWithRules(
		testControl,
		"Control",
		failedRule("m-rule", evidencePath{ReviewPath: "$.m"}),
		failedRule("b-rule", evidencePath{ReviewPath: "$.b"}),
	))

	first := computeReports(t, base, head)
	require.Len(t, first.New, 2)
	require.Len(t, first.Resolved, 2)
	assert.Equal(t, []string{"b-rule", "m-rule"}, []string{first.New[0].RuleName, first.New[1].RuleName})
	assert.Equal(t, []string{"a-rule", "z-rule"}, []string{first.Resolved[0].RuleName, first.Resolved[1].RuleName})

	for run := 0; run < 10; run++ {
		next := computeReports(t, base, head)
		assert.Equal(t, first, next)
	}
}

func TestGranularityValidation(t *testing.T) {
	tests := []struct {
		value   string
		want    Granularity
		wantErr bool
	}{
		{value: "", want: GranularityEvidence},
		{value: "evidence", want: GranularityEvidence},
		{value: "EVIDENCE", want: GranularityEvidence},
		{value: " evidence ", want: GranularityEvidence},
		{value: "control", want: GranularityControl},
		{value: "CONTROL", want: GranularityControl},
		{value: "path", wantErr: true},
		{value: "resource", wantErr: true},
		{value: "rule", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			actual, err := normalizeGranularity(Granularity(test.value))
			if test.wantErr {
				assert.ErrorContains(t, err, "invalid diff granularity")
				assert.Error(t, ValidateGranularity(test.value))
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.want, actual)
			assert.NoError(t, ValidateGranularity(test.value))
		})
	}
}

func TestFilterBySeverity_DoesNotMutateInput(t *testing.T) {
	input := []ControlChange{
		{ControlID: "critical", Severity: "Critical"},
		{ControlID: "low", Severity: "Low"},
		{ControlID: "high", Severity: "High"},
	}
	original := append([]ControlChange(nil), input...)

	filtered := FilterBySeverity(input, "high")

	assert.Equal(t, original, input)
	assert.Equal(t, []ControlChange{original[0], original[2]}, filtered)
}
