package cautils

import (
	"testing"

	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/stretchr/testify/assert"
)

func TestBuildScanCoverage_EmptyInfoMap(t *testing.T) {
	coverage := BuildScanCoverage(nil, map[string][]string{"apps/v1/deployments": {"C-0001"}}, nil, nil, nil)
	assert.Empty(t, coverage.FailedGVRPulls)
	assert.Empty(t, coverage.NotEvaluatedControls)
}

func TestBuildScanCoverage_NoFailedGVRs(t *testing.T) {
	infoMap := map[string]apis.StatusInfo{
		"networking.k8s.io/v1/networkpolicies": {InnerStatus: apis.StatusPassed},
	}
	coverage := BuildScanCoverage(infoMap, map[string][]string{"networking.k8s.io/v1/networkpolicies": {"C-0001"}}, nil, nil, nil)
	assert.Empty(t, coverage.FailedGVRPulls)
	assert.Empty(t, coverage.NotEvaluatedControls)
}

func TestBuildScanCoverage_FailedGVRPopulated(t *testing.T) {
	infoMap := map[string]apis.StatusInfo{
		"networking.k8s.io/v1/networkpolicies": {
			InnerStatus: apis.StatusSkipped,
			InnerInfo:   "RBAC denied",
		},
	}
	resourceToControlsMap := map[string][]string{
		"networking.k8s.io/v1/networkpolicies": {"C-0001"},
	}
	coverage := BuildScanCoverage(infoMap, resourceToControlsMap, nil, nil, nil)
	assert.Len(t, coverage.FailedGVRPulls, 1)
	assert.Equal(t, "networking.k8s.io/v1/networkpolicies", coverage.FailedGVRPulls[0].GVR)
	assert.Equal(t, "RBAC denied", coverage.FailedGVRPulls[0].Error)
}

func TestBuildScanCoverage_NoResourceMap(t *testing.T) {
	// Without a resourceToControlsMap, we cannot distinguish GVR keys from
	// resource-id keys, so we return empty rather than risk false positives.
	infoMap := map[string]apis.StatusInfo{
		"networking.k8s.io/v1/networkpolicies": {InnerStatus: apis.StatusSkipped},
	}
	coverage := BuildScanCoverage(infoMap, nil, nil, nil, nil)
	assert.Empty(t, coverage.FailedGVRPulls)
}

func TestBuildScanCoverage_AllGVRsFailedControlNotEvaluated(t *testing.T) {
	infoMap := map[string]apis.StatusInfo{
		"networking.k8s.io/v1/networkpolicies":      {InnerStatus: apis.StatusSkipped, InnerInfo: "RBAC denied"},
		"rbac.authorization.k8s.io/v1/clusterroles": {InnerStatus: apis.StatusSkipped, InnerInfo: "RBAC denied"},
	}
	resourceToControlsMap := map[string][]string{
		"networking.k8s.io/v1/networkpolicies":      {"C-0001", "C-0002"},
		"rbac.authorization.k8s.io/v1/clusterroles": {"C-0002"},
	}
	coverage := BuildScanCoverage(infoMap, resourceToControlsMap, nil, nil, nil)

	assert.Len(t, coverage.FailedGVRPulls, 2)

	// C-0001 depends on only networkpolicies which failed -> not evaluated
	// C-0002 depends on both which both failed -> not evaluated
	controlIDs := make(map[string][]string)
	for _, ne := range coverage.NotEvaluatedControls {
		controlIDs[ne.ControlID] = ne.MissingGVRs
	}
	assert.Contains(t, controlIDs, "C-0001")
	assert.Contains(t, controlIDs, "C-0002")
}

func TestBuildScanCoverage_IgnoresResourceLevelEvalSkips(t *testing.T) {
	// InfoMap is mixed-purpose: per-resource OPA eval skips use resource IDs
	// (e.g. "apps/v1/Deployment/default/my-app") as keys. These must NOT be
	// surfaced as failed GVR pulls.
	infoMap := map[string]apis.StatusInfo{
		"networking.k8s.io/v1/networkpolicies": {InnerStatus: apis.StatusSkipped, InnerInfo: "RBAC denied"},
		"apps/v1/Deployment/default/my-app":    {InnerStatus: apis.StatusSkipped, InnerInfo: "rego eval failed"},
		"apps/v1/Deployment/default/other-app": {InnerStatus: apis.StatusSkipped, InnerInfo: "rego eval failed"},
	}
	resourceToControlsMap := map[string][]string{
		"networking.k8s.io/v1/networkpolicies": {"C-0001"},
		"apps/v1/deployments":                  {"C-0002"},
	}
	coverage := BuildScanCoverage(infoMap, resourceToControlsMap, nil, nil, nil)

	// Only the GVR-keyed entry should be in FailedGVRPulls
	assert.Len(t, coverage.FailedGVRPulls, 1)
	assert.Equal(t, "networking.k8s.io/v1/networkpolicies", coverage.FailedGVRPulls[0].GVR)

	// C-0001 should be flagged not-evaluated, C-0002 should not
	assert.Len(t, coverage.NotEvaluatedControls, 1)
	assert.Equal(t, "C-0001", coverage.NotEvaluatedControls[0].ControlID)
}

func TestBuildScanCoverage_DeterministicOrder(t *testing.T) {
	// Same input run multiple times should produce identical output order.
	infoMap := map[string]apis.StatusInfo{
		"z/v1/zthings": {InnerStatus: apis.StatusSkipped, InnerInfo: "denied"},
		"a/v1/athings": {InnerStatus: apis.StatusSkipped, InnerInfo: "denied"},
		"m/v1/mthings": {InnerStatus: apis.StatusSkipped, InnerInfo: "denied"},
	}
	resourceToControlsMap := map[string][]string{
		"z/v1/zthings": {"C-0003"},
		"a/v1/athings": {"C-0001"},
		"m/v1/mthings": {"C-0002"},
	}

	first := BuildScanCoverage(infoMap, resourceToControlsMap, nil, nil, nil)
	for range 10 {
		next := BuildScanCoverage(infoMap, resourceToControlsMap, nil, nil, nil)
		assert.Equal(t, first, next)
	}

	// FailedGVRPulls sorted by GVR
	assert.Equal(t, "a/v1/athings", first.FailedGVRPulls[0].GVR)
	assert.Equal(t, "m/v1/mthings", first.FailedGVRPulls[1].GVR)
	assert.Equal(t, "z/v1/zthings", first.FailedGVRPulls[2].GVR)
	// NotEvaluatedControls sorted by ControlID
	assert.Equal(t, "C-0001", first.NotEvaluatedControls[0].ControlID)
	assert.Equal(t, "C-0002", first.NotEvaluatedControls[1].ControlID)
	assert.Equal(t, "C-0003", first.NotEvaluatedControls[2].ControlID)
}

func TestBuildScanCoverage_PartialGVRFailureControlStillEvaluated(t *testing.T) {
	// C-0001 depends on two GVRs but only one failed -> should NOT appear in NotEvaluatedControls
	infoMap := map[string]apis.StatusInfo{
		"networking.k8s.io/v1/networkpolicies": {InnerStatus: apis.StatusSkipped, InnerInfo: "RBAC denied"},
	}
	resourceToControlsMap := map[string][]string{
		"networking.k8s.io/v1/networkpolicies": {"C-0001"},
		"apps/v1/deployments":                  {"C-0001"},
	}
	coverage := BuildScanCoverage(infoMap, resourceToControlsMap, nil, nil, nil)

	assert.Len(t, coverage.FailedGVRPulls, 1)
	assert.Empty(t, coverage.NotEvaluatedControls)
}

func TestBuildScanCoverage_FailedGVRPullIsNotPhantomNotEvaluatedControl(t *testing.T) {
	// recordFailedQueryStatuses writes failed GVR pulls into InfoMap keyed by
	// GVR string using the same status pair as a timed-out control
	// (StatusSkipped + SubStatusNotEvaluated). Without resourceToControlsMap,
	// BuildScanCoverage must not surface this as a NotEvaluatedControl with the
	// GVR string as ControlID.
	infoMap := map[string]apis.StatusInfo{
		"networking.k8s.io/v1/networkpolicies": {
			InnerStatus: apis.StatusSkipped,
			SubStatus:   apis.SubStatusNotEvaluated,
			InnerInfo:   "failed to list resources",
		},
	}
	coverage := BuildScanCoverage(infoMap, nil, nil, nil, nil)

	for _, ne := range coverage.NotEvaluatedControls {
		assert.NotEqual(t, "networking.k8s.io/v1/networkpolicies", ne.ControlID)
	}
	assert.Empty(t, coverage.NotEvaluatedControls)
}

func TestComputeCoverageScore_FullCoverage(t *testing.T) {
	c := ScanCoverage{}
	c.ComputeCoverageScore(20)
	assert.Equal(t, float32(100), c.CoverageScore)
	assert.Equal(t, 20, c.EvaluatedControls)
	assert.Equal(t, 20, c.TotalControls)
	assert.False(t, c.Degraded)
}

func TestComputeCoverageScore_NotEvaluatedControlsReduceScore(t *testing.T) {
	c := ScanCoverage{
		NotEvaluatedControls: []NotEvaluatedControl{
			{ControlID: "C-0001"},
			{ControlID: "C-0002"},
		},
	}
	c.ComputeCoverageScore(10)
	assert.Equal(t, float32(80), c.CoverageScore)
	assert.Equal(t, 8, c.EvaluatedControls)
	assert.True(t, c.Degraded)
}

func TestComputeCoverageScore_PartialPullDiscount(t *testing.T) {
	c := ScanCoverage{
		PartialGVRPulls: []PartialGVRPull{
			{GVR: "/v1/pods", Selector: "metadata.namespace==prod"},
			{GVR: "core/v1/secrets", Selector: "metadata.name==s"},
		},
	}
	c.ComputeCoverageScore(10)
	// full control coverage minus 2 partial pulls * 2pp
	assert.Equal(t, float32(96), c.CoverageScore)
	assert.True(t, c.Degraded)
}

func TestComputeCoverageScore_PolicyDegradationDiscount(t *testing.T) {
	c := ScanCoverage{
		PolicyDegradations: []PolicyDegradation{
			{Component: "controlInputs", Reason: "network error"},
		},
	}
	c.ComputeCoverageScore(10)
	// full control coverage minus 1 degradation * 5pp
	assert.Equal(t, float32(95), c.CoverageScore)
	assert.True(t, c.Degraded)
}

func TestComputeCoverageScore_CombinedDiscountsClampedToZero(t *testing.T) {
	c := ScanCoverage{
		NotEvaluatedControls: []NotEvaluatedControl{{ControlID: "C-0001"}},
		PartialGVRPulls: []PartialGVRPull{
			{GVR: "/v1/pods", Selector: "a"},
		},
		PolicyDegradations: []PolicyDegradation{
			{Component: "exceptions", Reason: "forbidden"},
		},
	}
	c.ComputeCoverageScore(2)
	// 1/2 evaluated = 50, minus 2pp (partial) minus 5pp (degradation) = 43
	assert.Equal(t, float32(43), c.CoverageScore)
	assert.True(t, c.Degraded)
}

func TestComputeCoverageScore_ZeroControls(t *testing.T) {
	c := ScanCoverage{}
	c.ComputeCoverageScore(0)
	assert.Equal(t, float32(100), c.CoverageScore)
	assert.Equal(t, 0, c.EvaluatedControls)
	assert.False(t, c.Degraded)
}

func TestComputeCoverageScore_SilentFailedGVRReducesScore(t *testing.T) {
	// networkpolicies failed entirely, but C-0001 also depends on deployments
	// which succeeded, so it stays evaluated and is NOT in NotEvaluatedControls.
	// The failed GVR is therefore silent and must still reduce the score.
	infoMap := map[string]apis.StatusInfo{
		"networking.k8s.io/v1/networkpolicies": {InnerStatus: apis.StatusSkipped, InnerInfo: "RBAC denied"},
	}
	resourceToControlsMap := map[string][]string{
		"networking.k8s.io/v1/networkpolicies": {"C-0001"},
		"apps/v1/deployments":                  {"C-0001"},
	}
	coverage := BuildScanCoverage(infoMap, resourceToControlsMap, nil, nil, nil)
	assert.Len(t, coverage.FailedGVRPulls, 1)
	assert.Empty(t, coverage.NotEvaluatedControls)

	coverage.ComputeCoverageScore(10)
	assert.Less(t, coverage.CoverageScore, float32(100))
	assert.True(t, coverage.Degraded)
}

func TestComputeCoverageScore_MixedDependencyFailedGVRIsCharged(t *testing.T) {
	// networkpolicies feeds C-0001 (alone) and C-0002 (alongside deployments).
	// networkpolicies fails: C-0001 is NotEvaluated (only GVR failed), while
	// C-0002 still evaluates via deployments. The failure is therefore silent
	// for C-0002 and must incur the 3pp penalty, not just the ratio loss from
	// C-0001 being NotEvaluated.
	infoMap := map[string]apis.StatusInfo{
		"networking.k8s.io/v1/networkpolicies": {InnerStatus: apis.StatusSkipped, InnerInfo: "RBAC denied"},
	}
	resourceToControlsMap := map[string][]string{
		"networking.k8s.io/v1/networkpolicies": {"C-0001", "C-0002"},
		"apps/v1/deployments":                  {"C-0002"},
	}
	coverage := BuildScanCoverage(infoMap, resourceToControlsMap, nil, nil, nil)

	assert.Len(t, coverage.FailedGVRPulls, 1)
	assert.Len(t, coverage.NotEvaluatedControls, 1)
	assert.Equal(t, "C-0001", coverage.NotEvaluatedControls[0].ControlID)
	assert.Equal(t, 1, coverage.SilentFailedGVRCount)

	coverage.ComputeCoverageScore(10)
	// 9/10 evaluated = 90, minus 3pp for the silent failure on C-0002 = 87.
	assert.Equal(t, float32(87), coverage.CoverageScore)
	assert.True(t, coverage.Degraded)
}

func TestBuildScanCoverage_PartialGVRPullsPassedThrough(t *testing.T) {
	// Partial failures (GVR has some data, specific selector failed) must flow
	// into ScanCoverage.PartialGVRPulls so consumers can detect incomplete scans
	// without marking controls as NotEvaluated (the GVR still has partial data).
	partials := []PartialGVRPull{
		{GVR: "/v1/pods", Selector: "metadata.namespace==prod", Error: "RBAC denied for prod"},
		{GVR: "core/v1/secrets", Selector: "metadata.name==prod-secret", Error: "forbidden"},
	}
	coverage := BuildScanCoverage(nil, nil, nil, partials, nil)

	assert.Len(t, coverage.PartialGVRPulls, 2)
	assert.Equal(t, "/v1/pods", coverage.PartialGVRPulls[0].GVR)
	assert.Equal(t, "metadata.namespace==prod", coverage.PartialGVRPulls[0].Selector)
	assert.Contains(t, coverage.PartialGVRPulls[0].Error, "RBAC denied")
	assert.Empty(t, coverage.FailedGVRPulls)
	assert.Empty(t, coverage.NotEvaluatedControls)
}
