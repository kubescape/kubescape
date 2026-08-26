package opaprocessor

import (
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/assert"
)

// TestHasUnreachableDependency reproduces the exact shape of
// https://github.com/kubescape/kubescape/issues/3069: a control whose
// ResourceToControlsMap includes both a GVR that collected fine (e.g. Pod)
// and a GVR that failed (e.g. an RBAC 403 on ServiceAccount/RoleBinding).
// hasUnreachableDependency must say "yes, this control has an unreachable
// dependency" — the bug was that BuildScanCoverage's "all GVRs failed" gate
// never fires here because Pod alone keeps the set from being "all failed",
// even though the control's verdict genuinely depends on the missing data.
func TestHasUnreachableDependency(t *testing.T) {
	tests := []struct {
		name                  string
		infoMap               map[string]apis.StatusInfo
		resourceToControlsMap map[string][]string
		controlID             string
		want                  bool
	}{
		{
			name: "control depends on one failed GVR among several successful ones — C-0267 shape",
			infoMap: map[string]apis.StatusInfo{
				"/v1/serviceaccounts": {InnerStatus: apis.StatusSkipped, InnerInfo: "forbidden"},
			},
			resourceToControlsMap: map[string][]string{
				"/v1/pods":            {"C-0267"},
				"/v1/serviceaccounts": {"C-0267"},
				"rbac.authorization.k8s.io/v1/rolebindings":        {"C-0267"},
				"rbac.authorization.k8s.io/v1/clusterrolebindings": {"C-0267"},
			},
			controlID: "C-0267",
			want:      true,
		},
		{
			name: "control has no dependency on the failed GVR — unaffected",
			infoMap: map[string]apis.StatusInfo{
				"batch/v1/cronjobs": {InnerStatus: apis.StatusSkipped, InnerInfo: "forbidden"},
			},
			resourceToControlsMap: map[string][]string{
				"/v1/pods":          {"C-0267"},
				"batch/v1/cronjobs": {"C-OTHER"},
			},
			controlID: "C-0267",
			want:      false,
		},
		{
			name: "InfoMap entry exists but isn't a GVR pull failure (a per-resource eval skip, not in ResourceToControlsMap)",
			infoMap: map[string]apis.StatusInfo{
				"/v1/default/Pod/some-pod": {InnerStatus: apis.StatusSkipped, InnerInfo: "eval error"},
			},
			resourceToControlsMap: map[string][]string{
				"/v1/pods": {"C-0267"},
			},
			controlID: "C-0267",
			want:      false,
		},
		{
			name: "dependency GVR present but not skipped — collected fine",
			infoMap: map[string]apis.StatusInfo{
				"/v1/serviceaccounts": {InnerStatus: apis.StatusPassed},
			},
			resourceToControlsMap: map[string][]string{
				"/v1/pods":            {"C-0267"},
				"/v1/serviceaccounts": {"C-0267"},
			},
			controlID: "C-0267",
			want:      false,
		},
		{
			name:                  "no InfoMap entries at all — nothing failed",
			infoMap:               map[string]apis.StatusInfo{},
			resourceToControlsMap: map[string][]string{"/v1/pods": {"C-0267"}},
			controlID:             "C-0267",
			want:                  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := cautils.NewOPASessionObjMock()
			session.InfoMap = tt.infoMap
			session.ResourceToControlsMap = tt.resourceToControlsMap

			opap := NewOPAProcessor(session, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
			assert.Equal(t, tt.want, opap.hasUnreachableDependency(tt.controlID))
		})
	}
}
