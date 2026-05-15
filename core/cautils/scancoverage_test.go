package cautils

import (
	"testing"

	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/stretchr/testify/assert"
)

func TestBuildScanCoverage_EmptyInfoMap(t *testing.T) {
	coverage := BuildScanCoverage(nil, map[string][]string{"apps/v1/deployments": {"C-0001"}})
	assert.Empty(t, coverage.FailedGVRPulls)
	assert.Empty(t, coverage.NotEvaluatedControls)
}

func TestBuildScanCoverage_NoFailedGVRs(t *testing.T) {
	infoMap := map[string]apis.StatusInfo{
		"networking.k8s.io/v1/networkpolicies": {InnerStatus: apis.StatusPassed},
	}
	coverage := BuildScanCoverage(infoMap, map[string][]string{"networking.k8s.io/v1/networkpolicies": {"C-0001"}})
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
	coverage := BuildScanCoverage(infoMap, resourceToControlsMap)
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
	coverage := BuildScanCoverage(infoMap, nil)
	assert.Empty(t, coverage.FailedGVRPulls)
}

func TestBuildScanCoverage_AllGVRsFailedControlNotEvaluated(t *testing.T) {
	infoMap := map[string]apis.StatusInfo{
		"networking.k8s.io/v1/networkpolicies": {InnerStatus: apis.StatusSkipped, InnerInfo: "RBAC denied"},
		"rbac.authorization.k8s.io/v1/clusterroles": {InnerStatus: apis.StatusSkipped, InnerInfo: "RBAC denied"},
	}
	resourceToControlsMap := map[string][]string{
		"networking.k8s.io/v1/networkpolicies":          {"C-0001", "C-0002"},
		"rbac.authorization.k8s.io/v1/clusterroles":     {"C-0002"},
	}
	coverage := BuildScanCoverage(infoMap, resourceToControlsMap)

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
		"networking.k8s.io/v1/networkpolicies":  {InnerStatus: apis.StatusSkipped, InnerInfo: "RBAC denied"},
		"apps/v1/Deployment/default/my-app":     {InnerStatus: apis.StatusSkipped, InnerInfo: "rego eval failed"},
		"apps/v1/Deployment/default/other-app":  {InnerStatus: apis.StatusSkipped, InnerInfo: "rego eval failed"},
	}
	resourceToControlsMap := map[string][]string{
		"networking.k8s.io/v1/networkpolicies": {"C-0001"},
		"apps/v1/deployments":                  {"C-0002"},
	}
	coverage := BuildScanCoverage(infoMap, resourceToControlsMap)

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

	first := BuildScanCoverage(infoMap, resourceToControlsMap)
	for i := 0; i < 10; i++ {
		next := BuildScanCoverage(infoMap, resourceToControlsMap)
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
	coverage := BuildScanCoverage(infoMap, resourceToControlsMap)

	assert.Len(t, coverage.FailedGVRPulls, 1)
	assert.Empty(t, coverage.NotEvaluatedControls)
}
