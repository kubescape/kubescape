package opaprocessor

import (
	"context"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		partialPulls          []cautils.PartialGVRPull
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
		{
			name:    "partial conversion loss on a dependency GVR marks coverage incomplete",
			infoMap: map[string]apis.StatusInfo{},
			partialPulls: []cautils.PartialGVRPull{
				{GVR: "hostdata.kubescape.io/v1beta0/kubeletinfos", Selector: "conversion", Error: "node-agent reported 2 KubeletInfo but only 1 could be read"},
			},
			resourceToControlsMap: map[string][]string{
				"hostdata.kubescape.io/v1beta0/kubeletinfos": {"C-0267"},
				"/v1/pods": {"C-0267"},
			},
			controlID: "C-0267",
			want:      true,
		},
		{
			name:    "partial loss on an unrelated GVR does not affect the control",
			infoMap: map[string]apis.StatusInfo{},
			partialPulls: []cautils.PartialGVRPull{
				{GVR: "hostdata.kubescape.io/v1beta0/kubeletinfos", Selector: "conversion", Error: "node-agent reported 2 KubeletInfo but only 1 could be read"},
			},
			resourceToControlsMap: map[string][]string{
				"/v1/pods": {"C-0267"},
			},
			controlID: "C-0267",
			want:      false,
		},
		{
			name:    "partial entry for a GVR no control maps does not match anything",
			infoMap: map[string]apis.StatusInfo{},
			partialPulls: []cautils.PartialGVRPull{
				{GVR: "hostdata.kubescape.io/v1beta0/cniinfos", Selector: "conversion", Error: "node-agent reported 1 CNIInfo but only 0 could be read"},
			},
			resourceToControlsMap: map[string][]string{
				"/v1/pods": {"C-0267"},
			},
			controlID: "C-0267",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := cautils.NewOPASessionObjMock()
			session.InfoMap = tt.infoMap
			session.PartialGVRFailures = tt.partialPulls
			session.ResourceToControlsMap = tt.resourceToControlsMap

			opap := NewOPAProcessor(session, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
			assert.Equal(t, tt.want, opap.hasUnreachableDependency(tt.controlID))
		})
	}
}

// TestProcessRule_PartialGapTagsPassesIncomplete drives a rule over one
// passing and one failing resource with a partial gap on a mapped GVR: the
// pass must carry SubStatusIncompleteCoverage while the failure stays a
// plain failure.
func TestProcessRule_PartialGapTagsPassesIncomplete(t *testing.T) {
	rule := reporthandling.PolicyRule{
		PortalBase: armotypes.PortalBase{Name: "deny-bad-pod"},
		// NOTE: the package must be armo_builtins: runRegoOnK8s hardcodes its
		// query to data.armo_builtins, so any other package evaluates empty.
		Rule: `package armo_builtins
import rego.v1
deny contains msga if {
	wl := input[_]
	wl.metadata.name == "bad-pod"
	msga := {
		"alertMessage": "bad pod found",
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}`,
		Match: []reporthandling.RuleMatchObjects{
			{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Pod"}},
		},
		RuleQuery:    "test",
		RuleLanguage: reporthandling.RegoLanguage,
	}
	resourcesJSON := `{
		"/v1/default/Pod/good-pod": {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "good-pod", "namespace": "default"}},
		"/v1/default/Pod/bad-pod": {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "bad-pod", "namespace": "default"}}
	}`
	sessionJSON := `{
		"ResourceToControlsMap": {"/v1/pods": ["C-TEST"]},
		"PartialGVRFailures": [{"gvr": "/v1/pods", "selector": "conversion", "error": "node-agent reported 2 Pods but only 1 could be read"}],
		"K8SResources": {"/v1/pods": ["/v1/default/Pod/good-pod", "/v1/default/Pod/bad-pod"]}
	}`
	opap := NewOPAProcessorMock(sessionJSON, []byte(resourcesJSON))
	opap.Report = &reporthandlingv2.PostureReport{}
	control := &reporthandling.Control{ControlID: "C-TEST", Rules: []reporthandling.PolicyRule{rule}}

	got, err := opap.processRule(context.Background(), &rule, nil, evaluationScope{}, control)
	require.NoError(t, err)

	good, ok := got["/v1/default/Pod/good-pod"]
	require.True(t, ok, "passing pod must be present")
	assert.Equal(t, apis.StatusPassed, good.Status)
	assert.Equal(t, apis.SubStatusIncompleteCoverage, good.SubStatus)

	bad, ok := got["/v1/default/Pod/bad-pod"]
	require.True(t, ok, "failing pod must be present")
	assert.Equal(t, apis.StatusFailed, bad.Status)
	assert.NotEqual(t, apis.SubStatusIncompleteCoverage, bad.SubStatus, "readable failures must remain failures")
}
