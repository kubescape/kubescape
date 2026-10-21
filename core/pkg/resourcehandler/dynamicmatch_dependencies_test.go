package resourcehandler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/hostsensorutils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/diff"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const kubeletInfoGVR = "hostdata.kubescape.cloud/v1beta0/KubeletInfo"

func dynamicMatchOnControl(controlID string, groups, versions, resources []string) reporthandling.Control {
	return reporthandling.Control{
		ControlID: controlID,
		Rules: []reporthandling.PolicyRule{{DynamicMatch: []reporthandling.RuleMatchObjects{{
			APIGroups: groups, APIVersions: versions, Resources: resources,
		}}}},
	}
}

// TestSetComplexKSResourceMap_DynamicMatchUsesEvaluatorMatching checks that a
// DynamicMatch dependency is recorded for every Kubescape-served resource the
// evaluator would hand the rule, not only for exact resource names.
func TestSetComplexKSResourceMap_DynamicMatchUsesEvaluatorMatching(t *testing.T) {
	framework := reporthandling.Framework{Controls: []reporthandling.Control{
		dynamicMatchOnControl("C-EXACT", []string{"hostdata.kubescape.cloud"}, []string{"v1beta0"}, []string{"KubeletInfo"}),
		dynamicMatchOnControl("C-ANY-RESOURCE", []string{"hostdata.kubescape.cloud"}, []string{"v1beta0"}, []string{"*"}),
		dynamicMatchOnControl("C-LOWER-CASE", []string{"hostdata.kubescape.cloud"}, []string{"v1beta0"}, []string{"kubeletinfo"}),
		dynamicMatchOnControl("C-ANY-GROUP", []string{"*"}, []string{"*"}, []string{"KubeletInfo"}),
		dynamicMatchOnControl("C-OTHER-GROUP", []string{"example.com"}, []string{"v1beta0"}, []string{"*"}),
		dynamicMatchOnControl("C-CLOUD", []string{"*"}, []string{"v1"}, []string{"clusterdescribe"}),
	}}

	resourceToControls := map[string][]string{}
	setComplexKSResourceMap([]reporthandling.Framework{framework}, resourceToControls, defaultResourceResolver)

	got := slices.Clone(resourceToControls[kubeletInfoGVR])
	slices.Sort(got)
	assert.Equal(t, []string{"C-ANY-GROUP", "C-ANY-RESOURCE", "C-EXACT", "C-LOWER-CASE"}, got)
	assert.Contains(t, resourceToControls["hostdata.kubescape.cloud/v1beta0/KubeProxyInfo"], "C-ANY-RESOURCE")
	assert.NotContains(t, resourceToControls["hostdata.kubescape.cloud/v1beta0/KubeProxyInfo"], "C-EXACT")
	for _, controls := range resourceToControls {
		assert.NotContains(t, controls, "C-OTHER-GROUP")
	}
	for _, gvr := range []string{
		"container.googleapis.com/v1/ClusterDescribe",
		"eks.amazonaws.com/v1/ClusterDescribe",
		"management.azure.com/v1/ClusterDescribe",
	} {
		assert.Contains(t, resourceToControls[gvr], "C-CLOUD", gvr)
	}
}

// TestDynamicMatchWildcardFailedPullIsIncomparable runs the scenario from the
// review of #4258 from the producer to the diff: control A reads KubeletInfo
// by name, control B reads the same group and version with resources ["*"],
// both failed on the host in the base scan, and the KubeletInfo pull failed in
// the head scan. B was not evaluated, so its absence must not count as
// resolved. A control reading only Pods keeps resolving normally.
func TestDynamicMatchWildcardFailedPullIsIncomparable(t *testing.T) {
	framework := reporthandling.Framework{Controls: []reporthandling.Control{
		dynamicMatchOnControl("C-A", []string{"hostdata.kubescape.cloud"}, []string{"v1beta0"}, []string{"KubeletInfo"}),
		dynamicMatchOnControl("C-B", []string{"hostdata.kubescape.cloud"}, []string{"v1beta0"}, []string{"*"}),
		{ControlID: "C-PODS", Rules: []reporthandling.PolicyRule{{Match: []reporthandling.RuleMatchObjects{{
			APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Pod"},
		}}}}},
	}}
	resourceToControls := map[string][]string{}
	setComplexKSResourceMap([]reporthandling.Framework{framework}, resourceToControls, defaultResourceResolver)

	headCoverage := cautils.BuildScanCoverage(
		map[string]apis.StatusInfo{kubeletInfoGVR: {InnerStatus: apis.StatusSkipped, InnerInfo: "host sensor not available"}},
		resourceToControls, nil, nil, nil, nil,
		map[string]struct{}{"C-A": {}, "C-B": {}, "C-PODS": {}},
	)

	summary := map[string]any{"controls": map[string]any{
		"C-A":    map[string]any{"severity": "High"},
		"C-B":    map[string]any{"severity": "High"},
		"C-PODS": map[string]any{"severity": "High"},
	}}
	failed := func(controlID string) map[string]any {
		return map[string]any{"controlID": controlID, "name": controlID, "status": map[string]any{"status": "failed"}}
	}
	base := map[string]any{
		"results": []any{
			map[string]any{"resourceID": "node/worker", "controls": []any{failed("C-A"), failed("C-B")}},
			map[string]any{"resourceID": "default/Pod/web", "controls": []any{failed("C-PODS")}},
		},
		"summaryDetails": summary,
	}
	head := map[string]any{
		"results":        []any{},
		"summaryDetails": summary,
		"scanCoverage":   headCoverage,
	}

	changes, err := diff.Compute(writeJSONReport(t, base), writeJSONReport(t, head))
	require.NoError(t, err)

	resolved := map[string]bool{}
	for _, change := range changes.Resolved {
		resolved[change.ControlID] = true
	}
	incomparable := map[string]bool{}
	for _, change := range changes.Incomparable {
		incomparable[change.ControlID] = true
	}
	assert.True(t, incomparable["C-A"], "C-A read the failed pull")
	assert.True(t, incomparable["C-B"], "C-B read the failed pull through resources [\"*\"]")
	assert.False(t, resolved["C-B"])
	assert.True(t, resolved["C-PODS"], "C-PODS does not read the failed pull")
}

// TestDynamicMatchDependenciesAreCollected checks the contract between the
// collection plan and the dependency map: every Kubescape-served resource a
// control is recorded as depending on is also requested, so on a cluster
// without host data each of them gets a failure entry. Otherwise a dependency
// that was never requested reads as collected, and a control with no input
// counts as evaluated.
func TestDynamicMatchDependenciesAreCollected(t *testing.T) {
	framework := reporthandling.Framework{Controls: []reporthandling.Control{
		dynamicMatchOnControl("C-B", []string{"hostdata.kubescape.cloud"}, []string{"v1beta0"}, []string{"KubeletInfo", "*"}),
		dynamicMatchOnControl("C-LOWER-CASE", []string{"hostdata.kubescape.cloud"}, []string{"v1beta0"}, []string{"cloudProviderInfo"}),
		{ControlID: "C-PODS", Rules: []reporthandling.PolicyRule{{Match: []reporthandling.RuleMatchObjects{{
			APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Pod"},
		}}}}},
	}}
	resourceToControls := map[string][]string{}
	plan := setKSResourceMap([]reporthandling.Framework{framework}, resourceToControls, defaultResourceResolver)

	for gvr := range resourceToControls {
		if isExternalResource(gvr) {
			assert.Contains(t, plan, gvr, "dependency is not requested for collection")
		}
	}
	hostResources := cautils.MapHostResources(plan)
	assert.Len(t, hostResources, len(hostsensorutils.CollectedResources()))

	// No host sensor: the handler marks every requested host resource as skipped.
	infoMap := map[string]apis.StatusInfo{}
	cautils.SetInfoMapForResources("host sensor not available", hostResources, infoMap)
	coverage := cautils.BuildScanCoverage(infoMap, resourceToControls, nil, nil, nil, nil,
		map[string]struct{}{"C-B": {}, "C-LOWER-CASE": {}, "C-PODS": {}})
	coverage.ComputeCoverageScore(3)

	notEvaluated := make([]string, 0, len(coverage.NotEvaluatedControls))
	for _, control := range coverage.NotEvaluatedControls {
		notEvaluated = append(notEvaluated, control.ControlID)
	}
	slices.Sort(notEvaluated)
	assert.Equal(t, []string{"C-B", "C-LOWER-CASE"}, notEvaluated)
	assert.Equal(t, 1, coverage.EvaluatedControls)
	assert.Zero(t, coverage.SilentFailedGVRCount)
	assert.InDelta(t, 100.0/3, coverage.CoverageScore, 0.01)
}

func writeJSONReport(t *testing.T, report any) string {
	t.Helper()
	data, err := json.Marshal(report)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}
